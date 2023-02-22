#!/usr/bin/sage
# vim: syntax=python

F16 = GF(16, names=('x',))

# Turns an 8 bit abcdefgh int into a 32-bit int 000a000b000c000d000e000f000g000h
explode_table = [ int("".join([ "".join(x) for x in zip("00000000","00000000","00000000",bin(i+256)[3:])]),2) for i in range(256) ]
# inverse of explode
implode_dict = { explode_table[i]:i for i in range(256)}

def decode_vec(t, l):
    t = [(t[i//2] >> i % 2 * 4) & 0xf for i in range(2 * len(t))]
    v = vector(map(F16.fetch_int, t))

    if l % 2 == 1:
        v = v[:-1]
    return v

def encode_vec(v):
    if len(v) % 2 == 1:
        v  = vector(F16, v.list() + [ F16(0) ])
    bs = []
    for i in range(len(v)//2):
        bs += [v[i*2].integer_representation() |
               (v[i*2 + 1].integer_representation() << 4)]
    return bytes(bs)

def decode_matrix(t, rows, columns):
    t = decode_vec(t, len(t)*2)

    t = list(t[::-1])

    As = matrix(F16, rows, columns)
    for i in range(rows):
        for j in range(columns):
            As[i, j] = t.pop()

    return As

# Not used in "main" implementation, only for testing decode_matrix
def encode_matrix(mat, rows, columns):
    els = []
    for i in range(rows):
        for j in range(columns):
            els += [mat[i, j]]

    if len(els) % 2 == 1:
        els += [F16(0)]

    bs = encode_vec(els)
    return bytes(bs)

# Takes a tuple of four m-bit integers and outputs a vector of m field elements
def unbitslice_m_vec(tuple,m):
    assert len(tuple) == 4
    d0,d1,d2,d3 = tuple

    t = bytes()
    for x in range(m//8):
        t = t + int(explode_table[d0%256] + explode_table[d1%256]*2 + explode_table[d2%256]*4 + explode_table[d3%256]*8).to_bytes(4, byteorder='little');
        d0 //= 256
        d1 //= 256
        d2 //= 256
        d3 //= 256

    return decode_vec(t,m)

# Takes a vector of m field elements and output a tuple of four m-bit integers
def bitslice_m_vec(vec):
    assert len(vec) %32 == 0
    m = len(vec)

    d0,d1,d2,d3 = 0,0,0,0
    t = encode_vec(vec)

    for x in range(m//8,-1,-1):
        eight_elements = int.from_bytes(t[x*4:(x+1)*4], byteorder = 'little')
        d0 = d0*256 + implode_dict[      eight_elements & 0b00010001000100010001000100010001 ]
        d1 = d1*256 + implode_dict[ (eight_elements//2) & 0b00010001000100010001000100010001 ]
        d2 = d2*256 + implode_dict[ (eight_elements//4) & 0b00010001000100010001000100010001 ]
        d3 = d3*256 + implode_dict[ (eight_elements//8) & 0b00010001000100010001000100010001 ]

    return (d0,d1,d2,d3)

def partial_decode_matrices(t, m, rows, columns, triangular):
    """
    decode a string to a matrices of bitsliced vectors
    """

    assert m % 32 == 0
    bytes_per_vec = m//2
    bytes_per_deg = m//8
    bytes_used = 0

    matrices = [ [(0,0,0,0) for _ in range(columns)] for _ in range(rows) ]
    if triangular:
        assert rows == columns
        assert bytes_per_vec*(rows+1)*rows//2 == len(t)
        As = [matrix(F16, rows, columns) for _ in range(m)]
        for i in range(rows):
            for j in range(i, columns):
                matrices[i][j] = ( int.from_bytes(t[bytes_used+0*bytes_per_deg:bytes_used+1*bytes_per_deg], byteorder='little'),
                                   int.from_bytes(t[bytes_used+1*bytes_per_deg:bytes_used+2*bytes_per_deg], byteorder='little'),
                                   int.from_bytes(t[bytes_used+2*bytes_per_deg:bytes_used+3*bytes_per_deg], byteorder='little'),
                                   int.from_bytes(t[bytes_used+3*bytes_per_deg:bytes_used+4*bytes_per_deg], byteorder='little'))
                bytes_used += bytes_per_vec
    else:
        assert bytes_per_vec*rows*columns == len(t)
        As = [matrix(F16, rows, columns) for _ in range(m)]
        for i in range(rows):
            for j in range(columns):
                matrices[i][j] = ( int.from_bytes(t[bytes_used+0*bytes_per_deg:bytes_used+1*bytes_per_deg], byteorder='little'),
                                   int.from_bytes(t[bytes_used+1*bytes_per_deg:bytes_used+2*bytes_per_deg], byteorder='little'),
                                   int.from_bytes(t[bytes_used+2*bytes_per_deg:bytes_used+3*bytes_per_deg], byteorder='little'),
                                   int.from_bytes(t[bytes_used+3*bytes_per_deg:bytes_used+4*bytes_per_deg], byteorder='little'))
                bytes_used += bytes_per_vec

    return matrices

def decode_matrices(t, m, rows, columns, triangular):
    matrices = partial_decode_matrices(t, m, rows, columns, triangular)

    As = [matrix(F16, rows, columns) for _ in range(m)]

    for i in range(rows):
        for j in range(columns):
            if matrices[i][j] is None:
                continue

            v = unbitslice_m_vec(matrices[i][j], m)
            for k in range(m):
                As[k][i,j] = v[k]

    return As

def partial_encode_matrices(matrices, m, rows, columns, triangular):
    """
    encode set of m matrices to a matrix of bitsliced vectors
    """
    assert m % 32 == 0
    bytes_per_deg = m//8

    t = bytes()
    if triangular:
        assert rows == columns
        for i in range(rows):
            for j in range(i, columns):
                t += int(matrices[i][j][0]).to_bytes(bytes_per_deg, byteorder='little')
                t += int(matrices[i][j][1]).to_bytes(bytes_per_deg, byteorder='little')
                t += int(matrices[i][j][2]).to_bytes(bytes_per_deg, byteorder='little')
                t += int(matrices[i][j][3]).to_bytes(bytes_per_deg, byteorder='little')
        return t
    else:
        for i in range(rows):
            for j in range(columns):
                t += int(matrices[i][j][0]).to_bytes(bytes_per_deg, byteorder='little')
                t += int(matrices[i][j][1]).to_bytes(bytes_per_deg, byteorder='little')
                t += int(matrices[i][j][2]).to_bytes(bytes_per_deg, byteorder='little')
                t += int(matrices[i][j][3]).to_bytes(bytes_per_deg, byteorder='little')
        return t


def encode_matrices(mat, m, rows, columns, triangular):
    matrices = [ [None for _ in range(columns)] for _ in range(rows)]

    if triangular:
        for i in range(rows):
            for j in range(i, columns):
                matrices[i][j] = bitslice_m_vec([mat[k][i,j] for k in range(m)])
    else:
        for i in range(rows):
            for j in range(columns):
                matrices[i][j] = bitslice_m_vec([mat[k][i,j] for k in range(m)])

    return partial_encode_matrices(matrices, m, rows, columns, triangular)

def bitsliced_add(veca, vecb):
    a0,a1,a2,a3 = veca
    b0,b1,b2,b3 = vecb
    return (a0^^b0, a1^^b1, a2^^b2, a3^^b3)

def bitsliced_mul_add(In, a, Out):
    In0, In1, In2, In3 = In
    Out0, Out1, Out2, Out3 = Out
    a_int = a.integer_representation()

    if a_int & 1:
        Out0 ^^= In0
        Out1 ^^= In1
        Out2 ^^= In2
        Out3 ^^= In3

    In0, In1, In2, In3 = In3, In0^^In3, In1, In2
    if a_int & 2:
        Out0 ^^= In0
        Out1 ^^= In1
        Out2 ^^= In2
        Out3 ^^= In3

    In0, In1, In2, In3 = In3, In0^^In3, In1, In2
    if a_int & 4:
        Out0 ^^= In0
        Out1 ^^= In1
        Out2 ^^= In2
        Out3 ^^= In3

    In0, In1, In2, In3 = In3, In0^^In3, In1, In2
    if a_int & 8:
        Out0 ^^= In0
        Out1 ^^= In1
        Out2 ^^= In2
        Out3 ^^= In3

    return (Out0,Out1,Out2,Out3)

def bitsliced_matrices_matrix_mul(matrices, matrix):
    assert len(matrices[0]) == matrix.nrows()

    Out = [ [ (0,0,0,0) for _ in range(matrix.ncols())] for _ in range(len(matrices)) ]

    for i in range(len(matrices)):
        for j in range(matrix.ncols()):
            for k in range(matrix.nrows()):
                Out[i][j] = bitsliced_mul_add(matrices[i][k],matrix[k,j],Out[i][j])

    return Out

def bitsliced_matrix_matrices_mul(matrix,matrices):
    assert len(matrices) == matrix.ncols()

    Out = [ [ (0,0,0,0) for _ in range(len(matrices[0]))] for _ in range(matrix.nrows()) ]

    for i in range(matrix.nrows()):
        for j in range(len(matrices[0])):
            for k in range(matrix.ncols()):
                Out[i][j] = bitsliced_mul_add(matrices[k][j],matrix[i,k],Out[i][j])

    return Out

def bitsliced_matrices_add(matricesa,matricesb):
    assert len(matricesa) == len(matricesb)
    assert len(matricesa[0]) == len(matricesb[0])

    Out = [ [ None for _ in range(len(matricesa[0]))] for _ in range(len(matricesa)) ]

    for i in range(len(matricesa)):
        for j in range(len(matricesa[0])):
            Out[i][j] = bitsliced_add(matricesa[i][j],matricesb[i][j])

    return Out

def upper(p, rows):
    for j in range(0, rows):
        for k in range(j+1, rows):
            p[j, k] += p[k, j]
            p[k, j] = 0

    return p

def bitsliced_upper(matrices):
    rows = len(matrices)
    for j in range(0, rows):
        for k in range(j+1, rows):
            matrices[j][k] = bitsliced_add(matrices[j][k],matrices[k][j])
            matrices[k][j] = None

    return matrices
