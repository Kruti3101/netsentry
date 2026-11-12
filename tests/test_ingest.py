import gzip
import json

from netsentry.ingest import load_flows, read_conn_log, read_netflow_csv
from netsentry.ingest.export import write_netflow_csv, write_zeek_conn
from netsentry.models import FlowRecord

ZEEK_TSV = """#separator \\x09
#set_separator\t,
#empty_field\t(empty)
#unset_field\t-
#path\tconn
#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\thistory\torig_pkts\tresp_pkts
#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\tstring\tcount\tcount
1700000000.123456\tCabc\t10.0.1.5\t51000\t10.0.0.10\t443\ttcp\tssl\t0.5\t500\t1500\tSF\tShADadFf\t6\t5
1700000001.000000\tCdef\t203.0.113.9\t40000\t10.0.0.10\t22\ttcp\t-\t-\t-\t-\tS0\tS\t1\t0
#close\t2023-11-14-22-13-21
"""


def test_zeek_tsv(tmp_path):
    p = tmp_path / "conn.log"
    p.write_text(ZEEK_TSV)
    flows = list(read_conn_log(p))
    assert len(flows) == 2
    a, b = flows
    assert a.src == "10.0.1.5" and a.dport == 443 and a.service == "ssl" and a.conn_state == "SF"
    assert a.total_bytes == 2000 and not a.is_syn_only
    assert b.duration == 0.0 and b.orig_bytes == 0 and b.is_syn_only and b.failed


def test_zeek_json_and_gzip(tmp_path):
    p = tmp_path / "conn.log.gz"
    rows = [{"ts": 1.5, "id.orig_h": "1.2.3.4", "id.orig_p": 1, "id.resp_h": "5.6.7.8", "id.resp_p": 80,
             "proto": "tcp", "conn_state": "REJ", "history": "Sr"}]
    with gzip.open(p, "wt") as fh:
        fh.write("\n".join(json.dumps(r) for r in rows))
    (f,) = load_flows(p)
    assert f.dst == "5.6.7.8" and f.conn_state == "REJ" and f.is_syn_only


def test_netflow_nfdump_csv(tmp_path):
    p = tmp_path / "flows.csv"
    p.write_text("ts,te,td,sa,da,sp,dp,pr,flg,ipkt,ibyt\n"
                 "2023-11-14 22:13:20.000,2023-11-14 22:13:20.000,0.000,198.51.100.1,10.0.0.10,4444,443,TCP,....S.,1,40\n"
                 "2023-11-14 22:13:21.000,2023-11-14 22:13:22.500,1.500,10.0.1.5,10.0.0.53,5353,53,17,......,1,60\n"
                 "Summary\n")
    a, b = read_netflow_csv(p)
    assert a.proto == "tcp" and a.tcp_flags == "S" and a.is_syn_only
    assert b.proto == "udp" and b.duration == 1.5


def test_netflow_generic_aliases_and_int_flags(tmp_path):
    p = tmp_path / "x.csv"
    p.write_text("timestamp,src_ip,dst_ip,src_port,dst_port,protocol,tcp_flags,packets,bytes\n"
                 "1700000000,1.1.1.1,2.2.2.2,1000,80,6,18,3,120\n")
    (f,) = read_netflow_csv(p)
    assert f.tcp_flags == "SA" and f.orig_pkts == 3 and not f.is_syn_only


def test_export_roundtrip(tmp_path):
    flows = [FlowRecord(ts=1700000000.5, src="10.0.1.5", sport=50000, dst="10.0.0.10", dport=443, proto="tcp",
                        duration=0.3, orig_bytes=100, resp_bytes=200, orig_pkts=4, resp_pkts=3, conn_state="SF",
                        tcp_flags="SAF", orig_flags="SAF", resp_flags="SAF")]
    z = tmp_path / "c.log"
    n = tmp_path / "n.csv"
    write_zeek_conn(flows, z)
    write_netflow_csv(flows, n)
    (zf,) = read_conn_log(z)
    assert (zf.src, zf.dport, zf.conn_state, zf.orig_bytes) == ("10.0.1.5", 443, "SF", 100)
    fwd, rev = read_netflow_csv(n)       # unidirectional: one record per direction
    assert fwd.src == "10.0.1.5" and rev.src == "10.0.0.10" and rev.sport == 443
