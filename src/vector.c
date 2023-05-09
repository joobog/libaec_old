#include "vector.h"
#include <stdio.h>
#include <inttypes.h>
#include <assert.h>

#define VECTOR_FATAL_ERROR(...) \
    fprintf(stderr, "Fatal error in %s at line %d: ", __FILE__, __LINE__); \
    fprintf(stderr, __VA_ARGS__); \
    fprintf(stderr, "Exiting"); \
    exit(1);

#define VECTOR_OK 0
#define VECTOR_ERROR -1

#define VECTOR_INITIAL_CAPACITY 1
#define VECTOR_GROWTH_FACTOR 2

/**
 * Allocates memory for a new vector and initializes it with a default capacity.
 *
 * @return A pointer to the newly created vector. Returns NULL if memory allocation fails.
 */
struct vector_t* vector_create() {
  struct vector_t *vec = malloc(sizeof(struct vector_t));
  if (vec == NULL) {
    printf("Failed to allocate memory for vector\n");
    return NULL;
  }
  vector_init(vec, VECTOR_INITIAL_CAPACITY);
  return vec;
}

size_t vector_size(struct vector_t* vec) {
  return vec->size;
}

/**
 * Initializes a vector with given capacity.
 *
 * @param vec Pointer to the vector to be initialized.
 * @param capacity Capacity of the vector to be initialized.
 *
 * @exception assert Error occurs when capacity is not greater than 0.
 * @exception VECTOR_FATAL_ERROR Error occurs when memory allocation for vector values fails.
 */
void vector_init(struct vector_t *vec, size_t capacity) {
  assert(capacity > 0);
  vec->capacity = capacity;
  vec->size = 0;

  // Allocates memory for vector values.
  vec->values = malloc(sizeof(*vec->values) * vec->capacity);

  // Checks if memory allocation was successful.
  if (vec->values == NULL) {
    VECTOR_FATAL_ERROR("Failed to allocate memory for vector values\n");
  }
}

/**
 * @brief Deallocates the memory used by the vector and the vector itself.
 * 
 * The function releases the memory allocated by the vector and the vector
 * itself. The vector must have been previously initialized with vector_init()
 * 
 * @param vec Pointer to the vector to be destroyed.
 * 
 * @return void
 * 
 * @note After this function is called, the pointer to vec should not be used
 * anymore.
 * 
 * @see vector_init(), vector_init_with_capacity()
 */
void vector_destroy(struct vector_t *vec) {
  free(vec->values);
  free(vec);
}

/**
 * Compares two vector_t structs and returns 1 if they are equal, 1 otherwise.
 *
 * @param vec1 Pointer to the first vector_t struct to be compared.
 * @param vec2 Pointer to the second vector_t struct to be compared.
 *
 * @return Returns 0 if both vector_t structs are equal, 1 otherwise.
 */
int vector_equal(struct vector_t *vec1, struct vector_t *vec2) {
  if (vec1->size != vec2->size) {
    printf("Size mismatch: %zu != %zu\n", vec1->size, vec2->size);
    return 0;
  }
  for (size_t i = 0; i < vec1->size; i++) {
    if (vec1->values[i] != vec2->values[i]) {
      printf("Mismatch at pos %zu: %zu != %zu\n", i, vec1->values[i], vec2->values[i]);
      return 0;
    }
  }
  return 1;
}

/**
 * Retrieves the element at the specified index in the vector.
 *
 * @param vector the vector to retrieve the element from
 * @param idx the index of the element to retrieve
 * @return the value of the element at the specified index
 *
 * @pre vector must not be NULL
 * @pre idx must be less than the size of the vector
 * @throws assertion error if vector is NULL or idx is greater than or equal to the size of the vector
 */
size_t vector_at(struct vector_t *vector, size_t idx) {
  assert(vector != NULL);
  assert(idx < vector->size);
  return vector->values[idx];
}

/**
 * Adds a value to a vector.
 *
 * @param vec A pointer to the vector to which the value is to be added.
 * @param value The value to be added to the vector.
 * @return void
 *
 * If the vector is at its capacity, it will be resized by a factor of VECTOR_GROWTH_FACTOR
 * and the memory to hold its values will be reallocated. If reallocation fails, an error
 * message will be printed to stdout and the function will return immediately.
 */ 
void vector_push_back(struct vector_t *vec, size_t value) {
  if (vec->size == vec->capacity) {
    vec->capacity *= VECTOR_GROWTH_FACTOR;
    vec->values = realloc(vec->values, sizeof(*vec->values) * vec->capacity);
    if (vec->values == NULL) {
      printf("Failed to allocate memory for vector values\n");
      return;
    }
  }
  vec->values[vec->size] = value;
  vec->size++;
}


/**
 * @brief Removes the last element from the vector and returns it
 * 
 * @param vec Pointer to the vector_t struct
 * @return size_t The value of the removed element
 * 
 * @throws VECTOR_FATAL_ERROR if the vector is empty
 * 
 * @note The caller is responsible for freeing the memory of the removed element if it was dynamically allocated
 */
size_t vector_pop_back(struct vector_t *vec) {
  if (vec->size == 0) {
    VECTOR_FATAL_ERROR("Vector is empty\n");
  }
  vec->size--;
  return vec->values[vec->size];
}


void vector_print(struct vector_t *vec) {
  printf("Vector size: %zu\n", vec->size);
  for (size_t i = 0; i < vec->size; i++) {
    printf("pos: %zu value: %zu bits\n", i, vec->values[i]);
  }
}

