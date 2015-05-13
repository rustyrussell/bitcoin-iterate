This is some fast code to iterate over bitcoind's block files to
extract blockchain data from the main blockchain.

To build:
--------
1. make

Things you can do:
--------

.Show block hash and transaction size for each transaction in the main chain:
======
'./bitcoin-iterate -q --tx=%bh,%tl'

This will produce output like:
707a7706e0fc9fd2dac921c97d5c0b5e331c3b81513857030000000000000000,176
707a7706e0fc9fd2dac921c97d5c0b5e331c3b81513857030000000000000000,225
707a7706e0fc9fd2dac921c97d5c0b5e331c3b81513857030000000000000000,225
707a7706e0fc9fd2dac921c97d5c0b5e331c3b81513857030000000000000000,225
707a7706e0fc9fd2dac921c97d5c0b5e331c3b81513857030000000000000000,225
....
======

You can see some examples by looking at the [manual page source](https://github.com/rustyrussell/bitcoin-iterate/blob/master/doc/bitcoin-iterate.1.txt).

Enhancements
--------
Happy to consider them!

You can reach me on IRC (rusty on #bitcoin-wizards on Freenode), and
of course, via pull requests and the [Github bug
tracker](https://github.com/rustyrussell/bitcoin-iterate/issues).

Good luck!<br>
Rusty Russell.
