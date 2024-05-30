# tinyXDP
> Traffic ratelimit, tinyXDP!

The purpose is to mitigate DDoS by clearing traffic exceeding the rate limit through tinyXDP in a space that can be processed before the kernel. It's superfast, even dropped packets will not log.

![](https://github.com/minj-ae/tinyXDP/assets/65323308/e1dee385-11f2-4dad-b379-e9855b4d21d5)

## Requirements

### Debian

```sh

```


## Usage example

To attach tinyXDP, type

```sh
make
make load
make attach INTERFACE=yourinterfacename
```
To detach tinyXDP, type

```sh
make unload
make detach INTERFACE=yourinterfacename
```

## Development setup

Install `Requirements`

```sh


```

## Release History

* 0.1.0
    * The first proper release
    * CREATE: **TCP** ratelimit

* 0.2.0
    * ADD: **TCP** conntrack
    * ADD: **TCP** bogon FLAG check
    * ADD: endpoint ip whitelist adder
 
* 0.2.1
    * ADD: **TCP** conntrack advanced
    * EDIT: Change bogon FLAG check logic

## Meta

Minjae Kim – [minj.ae](https://minj.ae) – minjae@minj.ae

Distributed under the GPLv3 license. See ``LICENSE`` for more information.

[github.com/minj-ae](https://github.com/minj-ae)

## Contributing

1. Fork it (<https://github.com/minj-ae/tinyXDP>)
2. Create your feature branch (`git checkout -b feature/fooBar`)
3. Commit your changes (`git commit -am 'Add some fooBar'`)
4. Push to the branch (`git push origin feature/fooBar`)
5. Create a new Pull Request

