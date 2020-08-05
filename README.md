# jhash-fuzz
Fuzzing Jenkins hash for collisions

To build and run (clang only), do

```
$ clang -std=c++11 -fsanitize=fuzzer jhash-fuzzer.cc -o jhash-fuzz
$ ./jhash-fuzz
```
