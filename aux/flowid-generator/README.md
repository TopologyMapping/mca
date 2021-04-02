# mca-flowid-generator

This code generates high-entropy 16-bit flow identifiers for use in MCA.
Details are described in the original publication:

R. Almeida, Í. Cunha, R. Teixeira, D. Veitch, and C. Diot.
[Classification of Load Balancing in the Internet](https://doi.org/10.1109/INFOCOM41043.2020.9155387). IEEE INFOCOM, 2020.

Here is a short description of the flow identifier generation process:

Let `f[1], f[2], ..., f[n]` be the flow identifiers generated for the
first `n` probes.  We generate the new flow identifier `f[n+1]` greedily
bit-by-bit in random order.  The value of each bit is set such that it
maximizes the Shannon entropy of the distribution of values seen over
the `n+1` identifiers, restricted to the bits considered so far, with
ties broken randomly.  If the generated `f[n+1]` repeats an earlier
identifier, bits are randomly flipped until uniqueness is obtained.
