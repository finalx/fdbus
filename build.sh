cd $(dirname ${BASH_SOURCE[0]})

rm -rf cmake/build; mkdir -p cmake/build; pushd cmake/build
cmake -DCMAKE_INSTALL_PREFIX:PATH=./install ..
make -j32
popd


rm -rf cmake/pb-example/build; mkdir -p cmake/pb-example/build; pushd cmake/pb-example/build
cmake -DCMAKE_INSTALL_PREFIX:PATH=./install ..
make -j32
popd
