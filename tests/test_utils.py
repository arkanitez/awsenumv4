from app.enumerators.ec2 import classify_target_type, range_to_str, mk_id

def test_classify_target_type():
    assert classify_target_type('igw-123') == 'igw'
    assert classify_target_type('nat-xyz') == 'nat_gateway'
    assert classify_target_type('tgw-1') == 'tgw'
    assert classify_target_type('pcx-1') == 'pcx'
    assert classify_target_type('eni-1') == 'eni'
    assert classify_target_type('i-abc') == 'instance'
    assert classify_target_type('foo') == 'target'

def test_mk_id():
    assert mk_id('a','',None,'b') == 'a:b'
    assert mk_id('',None,'x') == 'x'
    assert mk_id('x','y') == 'x:y'

def test_range_to_str():
    assert range_to_str(80,80,'tcp') == '80'
    assert range_to_str(80,443,'tcp') == '80-443'
    assert range_to_str(None,None,'tcp') == 'all'
    assert range_to_str(0,0,'-1') == 'all'
