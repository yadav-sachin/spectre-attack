# SPECTRE ATTACK Variant 1

SPECTRE attack leverage the speculative Execution in modern processors. All the modern machines which use branch predictors are vulnerable to these attacks. Discovered by Google Zero team in 2017 and publicly announced in January 2018, Spectre and Meltdown mitigations has caused slowdown in the vulnerable machine.

Spectre attack is not a single security vulnerability, but a family of them. Here in this code, I have implemented the Conditional Branch variant, 'Variant 1' of Spectre attacks, which is to bypass the bounds check in the target program.

## Steps in the Spectre attack:

1. First the memory location of the target data must be known, using it we calculate the offset of the target data and accessible array pointers in memory.
2. For every byte of the data, we repeat the steps 2 to 8.
3. First we train the branch predictor by giving values which comply with the check bounds, making the branch predictor predict that the branch will be taken in future.
4. Now we make a malicious attack, that we pass a value to the target function which is out of bounds, that is the offset between the accessible array and target address in memory. The branch predictor now predicts branch taken.
5. As the branch predictor, now predicts the branch taken. The memoery at address array1 + offset gets prefetched into the cache.
6. After the memory is in the cache, we perform the 'timing attack'. For every character/byte between 0 to 255, we check the cycles it takes to fetch it from memory. If it is less or equal to the time threshold, then we assume that the data is in Cache, otherwise not.
7. We repeat step 3 to step 6, multiple times. In every try, we check for all the 256 values in the byte memory. Using the step 6, we calculate the scores for every value in 0 to 256, denoting its likeliness to be at the target data.
8. Now we sort the results in descending order to get the top scores.
9. Now based on the scores and results for every byte we make the best guess.

## File Structure
```shell
.
├── main.cpp
├── Makefile
├── presentation.pdf
└── README.md
```

## Running the Files

1. Complile the file
   ```shell
   $ make
   ```
2. Run the file directly
   ```shell
   $ ./spectre
   ```


## Program Structure in main.cpp


## Resources for Spectre Attack       
Check out these resources to learn more about Spectre attacks:
- Papers
  - [Spectre Attacks: Exploiting Speculative Execution](https://spectreattack.com/spectre.pdf)
- YouTube Videos
  - [Spectre and Meltdown: Data leaks during speculative execution | J. Horn (Google Project Zero)](https://youtu.be/6O8LTwVfTVs)
  - [Spectre Attacks Exploiting Speculative Execution -- IEEE Symposium](https://youtu.be/zOvBHxMjNls)
- Websites
  - [Meltdown and Spectre](https://spectreattack.com/)
