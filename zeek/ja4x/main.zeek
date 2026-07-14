# Copyright (c) 2024, FoxIO, LLC.
# All rights reserved.
# Licensed under FoxIO License 1.1
# For full license text and more details, see the repo root https://github.com/FoxIO-LLC/ja4
# JA4+ by John Althouse
# JA4X Zeek implementation.
#
# JA4X fingerprints the server's X.509 certificate:
#   JA4X = <issuer_hash>_<subject_hash>_<extension_hash>
# where each hash is sha256(",".join(DER-hex of each OID))[:12], over:
#   - the Issuer RDN OIDs, in certificate (DER) order,
#   - the Subject RDN OIDs, in certificate (DER) order,
#   - the certificate extension OIDs, in order.
#
# Zeek exposes extension OIDs directly (x509_extension$oid) but issuer/subject
# only as formatted DN strings (RFC2253, which reverses RDN order). We therefore
# map DN attribute short-names -> OIDs, reverse to DER order, and hash. This was
# validated to reproduce tshark's native ja4.ja4x on real certificates.

@load ../config
@load ../utils/common
@load base/protocols/ssl
@load base/files/x509

module FINGERPRINT::JA4X;

export {
  type Info: record {
    # The connection uid which this fingerprint represents
    uid: string &log &optional;
    # The JA4X fingerprint of the connection's leaf certificate
    ja4x: string &log &default="";
    # If this context has been computed
    done: bool &default=F;
  };

  redef enum Log::ID += { LOG };
  global log_fingerprint_ja4x: event(rec: Info);
  global log_policy: Log::PolicyHook;

  # DN attribute short-name -> dotted OID. Extend via redef for exotic attrs;
  # an unknown (unmappable) attribute makes JA4X empty for that certificate so
  # we never emit a wrong fingerprint.
  const dn_oid_map: table[string] of string = {
    ["CN"] = "2.5.4.3",
    ["C"] = "2.5.4.6",
    ["L"] = "2.5.4.7",
    ["ST"] = "2.5.4.8",
    ["O"] = "2.5.4.10",
    ["OU"] = "2.5.4.11",
    ["SN"] = "2.5.4.4",
    ["serialNumber"] = "2.5.4.5",
    ["title"] = "2.5.4.12",
    ["GN"] = "2.5.4.42",
    ["givenName"] = "2.5.4.42",
    ["initials"] = "2.5.4.43",
    ["street"] = "2.5.4.9",
    ["postalCode"] = "2.5.4.17",
    ["businessCategory"] = "2.5.4.15",
    ["dnQualifier"] = "2.5.4.46",
    ["pseudonym"] = "2.5.4.65",
    ["organizationIdentifier"] = "2.5.4.97",
    ["emailAddress"] = "1.2.840.113549.1.9.1",
    ["DC"] = "0.9.2342.19200300.100.1.25",
    ["UID"] = "0.9.2342.19200300.100.1.1",
  } &redef;
}

type CertMaterial: record {
  issuer: string &default="";
  subject: string &default="";
  exts: vector of string &default=vector();
};

redef record FINGERPRINT::Info += {
  ja4x: FINGERPRINT::JA4X::Info &default=Info();
};

redef record SSL::Info += {
  ja4x: string &log &default="";
};

# Per-certificate material, keyed by file id (fuid). Certs are shared across
# connections to the same server, so entries are kept for the trace's lifetime.
global cert_material: table[string] of CertMaterial;

event zeek_init() &priority=5 {
  Log::create_stream(FINGERPRINT::JA4X::LOG,
    [$columns=FINGERPRINT::JA4X::Info, $ev=log_fingerprint_ja4x,
     $path="fingerprint_ja4x", $policy=log_policy]);
}

# --- OID DER content encoding (matches the JA4X reference oid_to_hex) ---------

# Variable-length quantity (base-128) bytes for one sub-identifier, big-endian
# with the continuation bit (0x80) set on all but the least-significant byte.
function vlq_bytes(v: count): vector of count {
  local tmp: vector of count = vector();
  local m = 0;
  local val = v;
  while (val >= 128) {
    tmp += ((val % 128) + m);
    val = val / 128;
    m = 128;
  }
  tmp += (val + m);
  # tmp is least-significant-first; reverse to big-endian
  local out: vector of count = vector();
  local i = |tmp|;
  while (i > 0) { i = i - 1; out += tmp[i]; }
  return out;
}

# Dotted OID -> hex of its DER content bytes (no tag/length prefix).
function oid_to_hex(oid: string): string {
  local parts = split_string(oid, /\./);
  if (|parts| < 2) return "";
  local bs: vector of count = vector();
  bs += (to_count(parts[0]) * 40 + to_count(parts[1]));
  local i = 2;
  while (i < |parts|) {
    local grp = vlq_bytes(to_count(parts[i]));
    local j = 0;
    while (j < |grp|) { bs += grp[j]; j = j + 1; }
    i = i + 1;
  }
  local s = "";
  local k = 0;
  while (k < |bs|) { s = s + fmt("%02x", bs[k]); k = k + 1; }
  return s;
}

# Raw sha256[:12] (NOT the null-variant: an empty list must hash to sha256("")).
function sha256_12(input: string): string {
  local o = sha256_hash_init();
  sha256_hash_update(o, input);
  return sha256_hash_finish(o)[:12];
}

function is_num_oid(k: string): bool {
  if (k == "") return F;
  local i = 0;
  while (i < |k|) {
    local ch = k[i];
    if (ch != "." && (ch < "0" || ch > "9")) return F;
    i = i + 1;
  }
  return T;
}

# DN string -> vector of dotted OIDs (an empty entry marks an unmappable attr).
function dn_to_oids(dn: string): vector of string {
  local out: vector of string = vector();
  local parts = split_string(dn, /,/);
  local idx = 0;
  while (idx < |parts|) {
    local kv = split_string1(parts[idx], /=/);
    if (|kv| >= 2) {
      local key = strip(kv[0]);
      if (key in dn_oid_map) out += dn_oid_map[key];
      else if (is_num_oid(key)) out += key;
      else out += "";
    }
    idx = idx + 1;
  }
  return out;
}

function reverse_str_vec(v: vector of string): vector of string {
  local out: vector of string = vector();
  local i = |v|;
  while (i > 0) { i = i - 1; out += v[i]; }
  return out;
}

function hash_oids(oids: vector of string): string {
  local hexes: vector of string = vector();
  local i = 0;
  while (i < |oids|) { hexes += oid_to_hex(oids[i]); i = i + 1; }
  return sha256_12(FINGERPRINT::vector_of_str_to_str(hexes, "%s", ","));
}

function compute_ja4x(m: CertMaterial): string {
  local io = dn_to_oids(m$issuer);
  local so = dn_to_oids(m$subject);
  # Bail (empty JA4X) if any DN attribute could not be mapped to an OID.
  local i = 0;
  while (i < |io|) { if (io[i] == "") return ""; i = i + 1; }
  i = 0;
  while (i < |so|) { if (so[i] == "") return ""; i = i + 1; }
  # RFC2253 DN order is reversed vs the certificate/DER order JA4X uses.
  io = reverse_str_vec(io);
  so = reverse_str_vec(so);
  return fmt("%s_%s_%s", hash_oids(io), hash_oids(so), hash_oids(m$exts));
}

event x509_certificate(f: fa_file, cert_ref: opaque of x509, cert: X509::Certificate) {
  cert_material[f$id] = CertMaterial($issuer=cert$issuer, $subject=cert$subject);
}

event x509_extension(f: fa_file, ext: X509::Extension) {
  if (f$id in cert_material) {
    cert_material[f$id]$exts += ext$oid;
  }
}

function do_ja4x(c: connection) {
  if (!c?$fp) { c$fp = FINGERPRINT::Info(); }
  if (c$fp$ja4x$done) { return; }
  if (!c?$ssl || !c$ssl?$cert_chain || |c$ssl$cert_chain| == 0) { return; }
  local leaf = c$ssl$cert_chain[0];         # leaf (end-entity) cert
  if (!leaf?$fuid) { return; }
  local fuid = leaf$fuid;
  if (fuid !in cert_material) { return; }

  c$fp$ja4x$uid = c$uid;
  c$fp$ja4x$ja4x = compute_ja4x(cert_material[fuid]);
  c$ssl$ja4x = c$fp$ja4x$ja4x;
  c$fp$ja4x$done = T;
}

event connection_state_remove(c: connection) {
  do_ja4x(c);
}

hook SSL::log_policy(rec: SSL::Info, id: Log::ID, filter: Log::Filter) {
  if (connection_exists(rec$id)) {
    do_ja4x(lookup_connection(rec$id));
  }
}
