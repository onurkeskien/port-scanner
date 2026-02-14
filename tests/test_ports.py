from port_scanner.cli import parse_ports

def test_parse_ports_single():
    assert parse_ports("80") == [80]

def test_parse_ports_list():
    assert parse_ports("22,80,443") == [22, 80, 443]

def test_parse_ports_range():
    assert parse_ports("1-3") == [1, 2, 3]

def test_parse_ports_mix():
    assert parse_ports("22,80,100-102") == [22, 80, 100, 101, 102]