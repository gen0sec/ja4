# @TEST-EXEC: zeek -C -r ${TRACES}/tls3.pcapng ../../../__load__.zeek %INPUT
# @TEST-EXEC: btest-diff conn.log
