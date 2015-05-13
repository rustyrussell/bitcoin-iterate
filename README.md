This is some fast code to iterate over bitcoind's block files to
extract blockchain data from the main blockchain.

## To build:

1. make

## Things you can do:

Show block hash and transaction size for each transaction in the main chain:

	./bitcoin-iterate -q --tx=%bh,%tl

This will produce output like:

	6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000,204
	4860eb18bf1b1620e37e9490fc8a427514416fd75159ab86688e9a8300000000,134
	bddd99ccfda39da1b108ce1a5d70038d0a967bacb68b6b63065f626a00000000,134
	4944469562ae1c2c74d9a535e00b6f3e40ffbad4f2fda3895501b58200000000,134
	85144a84488ea88d221c8bd6c059da090e88f8a2c99690ee55dbba4e00000000,134
&hellip;

Show output script sizes in the main chain (block number, transaction
number, output number, output script length):

	./bitcoin-iterate -q --output=%bN,%tN,%oN:%ol

This will produce output like:

	0,0,0:67
	1,0,0:67
	2,0,0:67
	3,0,0:67
	4,0,0:67
&hellip;

Show the five largest blocks, by height and blockhash:

	./bitcoin-iterate -q --block='%bl %bN %bh' | sort -nr | head -n5

This will produce output like:

	999993 343188 96395be50a116886fb04a1262aa89aaa765c4af524d0ae090000000000000000
	999991 355770 5ce1f5e58d5d718374b1bdecb474eae5cdd91e1b8a3256050000000000000000
	999990 327145 821196665ed237f53ca2c7eafe05c97d26743c07d2b539110000000000000000
	999989 345578 0294fa5b68babd848a1fe097b075a856bfd9eb9a619efd130000000000000000
	999989 333434 f9776021575b6e408d7745d115db75e17937fc40ab9f0e190000000000000000
&hellip;

You can see some examples by looking at the [manual page source](https://github.com/rustyrussell/bitcoin-iterate/blob/master/doc/bitcoin-iterate.1.txt).

## Enhancements

Happy to consider them!

You can reach me on IRC (rusty on #bitcoin-wizards on Freenode), and
of course, via pull requests and the [Github bug
tracker](https://github.com/rustyrussell/bitcoin-iterate/issues).

Good luck!<br>
Rusty Russell.
