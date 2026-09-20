#include <core/app.hpp>

int main(int argc, char* argv[]) {
    app_t app(argc, argv);

    if (!app.setup("decompatty", 1280, 800))
        return 1;

    return app.run();
}