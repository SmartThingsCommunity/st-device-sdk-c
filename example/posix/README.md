# _POSIX switch example_

## Build environment

1. Ubuntu 18.04, 20.04

1. apt-get install git cmake libglib2.0-dev libssl-dev libpthread-stubs0-dev

## How to build example

1. Build a POSIX example application.

    ```sh
    $ cd st-device-sdk-c/example/posix
    $ cmake -B build
    $ cd build
    $ make
    ```

2. Excute example.

    ```sh
    $ ./example
    ```

Please refer [Getting Started](../../doc/getting_started.md) guide for testing example with ST app.
