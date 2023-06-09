cd SEAL
cmake -S . -B build -DCMAKE_INSTALL_PREFIX=./../lib/SEAL
cmake --build build
cmake --install build