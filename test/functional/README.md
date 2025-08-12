# Functional tests

Make sure the workspace is liquid:

```bash
cd ../..
./autogen.sh
./configure
cd test/functional
```

Prepare the testing framework with

```bash
./1-setup.sh
```

Then run the test as many times as you need while debugging:

```bash
./2-test.sh
```

Once you're done, optionally clean up with

```bash
./3-cleanup.sh
```
