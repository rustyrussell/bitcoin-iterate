#! /usr/bin/make

# This isn't quite right, could be 2 bytes longer for > 252 txs.
BLOCK_HDRLEN=81

# Gregory Maxwell suggested this random number (~= 6 hours)
GROUP_SIZE=36

default: blocksize-variants.csv blocksize-variants-grouped-$(GROUP_SIZE).csv

clean:
	$(RM) *.csv

# All outputs [blockheight,txnum,txlen,amount]
outputs.csv:
	../bitcoin-iterate -q --output=%bN,%tN,%tl,%oa > $@

# Eliminate outputs which have an all ASCII output of at least 20
# bytes (so false positive rate ~ 1 in million).
outputs-nospam.csv:
	../bitcoin-iterate -q --output=%bN,%tN,%tl,%to,%os | grep -v ',\([0-9a-f][0-9a-f]\)*\([234567].\)\{20,\}' > $@

# We do this by filtering out all-ascii outputs (above), and only
# printing txs if they still have all their outputs.
# => [blockheight,txnum,txlen]
transaction-nospam.csv: outputs-nospam.csv
	awk -F, 'BEGIN { PREV="0,0"; LEN=0; TOT_OUTS=0; NUM=0 } { if ($$1","$$2 != PREV) { if (NUM == TOT_OUTS || $$2 == 1) print PREV","LEN; NUM=0; PREV=$$1","$$2 } LEN=$$3; TOT_OUTS=$$4; NUM++ }' < $< > $@

# Now, keep txs which have 0 or 1 outputs < minimum => [blockheight,txnum,len]
# Always keep coinbases.
transaction-min-%.csv: outputs.csv
	awk -F, 'BEGIN { PREVB=0; PREVTX=0; LEN=0; TOO_LOW=0 } { if ($$1","$$2 != PREVB","PREVTX) { if (TOO_LOW <= 1 || PREVTX == 0) print PREVB","PREVTX","LEN; TOO_LOW=0; PREVB=$$1; PREVTX=$$2} LEN=$$3; if ($$4 < $*) TOO_LOW++; }' < $< > $@

# Now recalculate block sizes by summing transactions => [len]
blocks-%.csv: transaction-%.csv
	(echo '$*'; awk -F, 'BEGIN { PREV="0"; LEN=$(BLOCK_HDRLEN) } { if ($$1 != PREV) { print LEN; PREV=$$1; LEN=$(BLOCK_HDRLEN);} LEN+=$$3 }' < $<) > $@

# Actual unchanged stats.
normal-blocksize.csv:
	(echo 'Normal'; ../bitcoin-iterate -q --block=%bl) > $@

# Chunked stats: preserve top line, chunk the rest into averages.
grouped-$(GROUP_SIZE)-%.csv: %.csv
	awk -F, 'BEGIN { COUNT=0; SIZE=0 } { if (COUNT == 0) { print $0; } else { SIZE+=$$1; if (COUNT % $(GROUP_SIZE) == 0) { print int(SIZE/$(GROUP_SIZE)); SIZE=0 } } COUNT++ }' < $< > $@

# Merge them together to get single [blocknum,<len1>,<len2> ...
blocksize-variants.csv: normal-blocksize.csv blocks-min-5000.csv blocks-min-50000.csv blocks-min-500000.csv blocks-min-1000000.csv blocks-min-5000000.csv blocks-min-10000000.csv blocks-nospam.csv
	(echo 'Block height'; seq 0 `wc -l < $<`) | paste -d, - $^ > $@

blocksize-variants-grouped-%.csv: grouped-%-normal-blocksize.csv grouped-%-blocks-min-5000.csv grouped-%-blocks-min-50000.csv grouped-%-blocks-min-500000.csv grouped-%-blocks-min-1000000.csv grouped-%-blocks-min-5000000.csv grouped-%-blocks-min-10000000.csv grouped-%-blocks-nospam.csv
	(echo 'Block height'; seq 0 $* $$((`wc -l < $<` * $*)) ) | paste -d, - $^ > $@
