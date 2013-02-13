#include "../core/loop.h"

int main(int argc, const char* argv[]) {
	(void) argc;
	(void) argv;

	struct loop *loop = loop_create();
	// TODO: Load all the plugins here.
	loop_run(loop);
	// TODO: Release all the plugins here.
	loop_destroy(loop);
	return 0;
}
