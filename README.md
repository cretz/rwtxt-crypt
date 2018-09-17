# rwtxt-crypt

This is a version of [rwtxt](https://github.com/schollz/rwtxt) that adds
[Sqlite encryption](https://github.com/cretz/go-sqleet) and [Tor support](https://github.com/cretz/bine). More docs
coming soon...

Note, due to a bug, to reuse the same onion service address with the `-onionKey` CLI arg, a version of Tor at least
`0.3.3.5` is required which is just now entering alpha state. I'll probably be
[statically linking Tor](https://github.com/cretz/tor-static) anyways before I'm done.