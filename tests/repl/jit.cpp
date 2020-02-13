#include <EXTLLVMGlobalMap.h>

int main(int argc, char **argv) {
  if (sGlobalMap.count("hello") == 1) {
    return 1;
  }

  return 0;
}
