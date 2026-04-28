# @TEST-EXEC: zeek -C -r ${TRACES}/chrome-cloudflare-quic-with-secrets.pcapng ../../../__load__.zeek %INPUT
# @TEST-EXEC: btest-diff conn.log
