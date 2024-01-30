# Tests

Start all containers for testing:

```shell
$ ./dc-up.sh
```

To update the client container kpx in the running container:

```shell
$ ./dc-up.sh -d client
```

Then use the `tests-*.sh` scripts do execute the tests:

```shell
$ ./tests-http.sh
$ ./tests-pac.sh
$ ./tests-rewrite.sh
```
