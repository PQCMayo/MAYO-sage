#!/usr/bin/sage
# vim: syntax=python

F16.<x> = GF(16)

field_elt_from_integer = {}
field_elt_from_integer[0] = F16(0)
field_elt_from_integer[1] = F16(1)
field_elt_from_integer[2] = F16(x)
field_elt_from_integer[3] = F16(1 + x)
field_elt_from_integer[4] = F16(x**2)
field_elt_from_integer[5] = F16(1 + x**2)
field_elt_from_integer[6] = F16(x + x**2)
field_elt_from_integer[7] = F16(1 + x + x**2)
field_elt_from_integer[8] = F16(x**3)
field_elt_from_integer[9] = F16(1 + x**3)
field_elt_from_integer[10] = F16(x + x**3)
field_elt_from_integer[11] = F16(1 + x + x**3)
field_elt_from_integer[12] = F16(x**2 + x**3)
field_elt_from_integer[13] = F16(1 + x**2 + x**3)
field_elt_from_integer[14] = F16(x + x**2 + x**3)
field_elt_from_integer[15] = F16(1 + x + x**2 + x**3)

integer_from_field_elt = { felt : i for i, felt in field_elt_from_integer.items() }

def decode_vec(t, l):
    t = [(t[i//2] >> i % 2 * 4) & 0xf for i in range(2 * len(t))]
    v = vector(map(lambda x : field_elt_from_integer[x], t))

    if l % 2 == 1:
        v = v[:-1]
    return v

def encode_vec(v):
    if len(v) % 2 == 1:
        v  = vector(F16, v.list() + [ F16(0) ])
    bs = []
    for i in range(len(v)//2):
        bs += [integer_from_field_elt[v[i*2]] |
               (integer_from_field_elt[v[i*2 + 1]] << 4)]
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

def decode_matrices(t, m, rows, columns, triangular):
    assert m % 2 == 0
    bytes_used = 0

    if triangular:
        assert rows == columns
        assert (m//2)*(rows+1)*rows//2 == len(t)

        As = [matrix(F16, rows, columns) for _ in range(m)]
        for i in range(rows):
            for j in range(i, columns):
                for k in range(m//2):
                    byte = t[bytes_used]
                    bytes_used += 1
                    As[k*2 + 0][i,j] = field_elt_from_integer[byte & 0xF]
                    As[k*2 + 1][i,j] = field_elt_from_integer[byte >> 4]
    else:
        assert (m//2)*rows*columns == len(t)
        As = [matrix(F16, rows, columns) for _ in range(m)]
        for i in range(rows):
            for j in range(columns):
                for k in range(m//2):
                    byte = t[bytes_used]
                    bytes_used += 1
                    As[k*2 + 0][i,j] = field_elt_from_integer[byte & 0xF]
                    As[k*2 + 1][i,j] = field_elt_from_integer[byte >> 4]
    return As

def encode_matrices(mat, m, rows, columns, triangular):
    t = bytes()
    if triangular:
        for i in range(rows):
            for j in range(i, columns):
                for k in range(m//2):
                    b0 = integer_from_field_elt[mat[2*k + 0][i, j]]
                    b1 = integer_from_field_elt[mat[2*k + 1][i, j]]

                    t += int(b0 + (b1 << 4)).to_bytes(1,"little")
    else:
        As = [matrix(F16, rows, columns) for _ in range(m)]
        for i in range(rows):
            for j in range(columns):
                for k in range(m//2):
                    b0 = integer_from_field_elt[mat[2*k + 0][i, j]]
                    b1 = integer_from_field_elt[mat[2*k + 1][i, j]]

                    t += int(b0 + (b1 << 4)).to_bytes(1,"little")
    return t


def upper(p, rows):
    for j in range(0, rows):
        for k in range(j+1, rows):
            p[j, k] += p[k, j]
            p[k, j] = 0

    return p

