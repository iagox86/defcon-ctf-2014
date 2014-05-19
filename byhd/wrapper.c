#include <unistd.h>

int main(int argc, const char *argv[])
{
  execlp("/home/byhd/fixed/byhd", "/home/byhd/byhd", NULL);

  printf("Fail :(\n");
  return 0;
}
