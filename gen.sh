# locate the directory of the script
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
echo $DIR

# locate the root directory
ROOT_DIR="$DIR/.."
RUST_SRC_DIR="$ROOT_DIR/src"
OPCODES_DIR="$ROOT_DIR/riscv-opcodes"

# generate the riscv-opcodes
make inst.rs EXTENSIONS='rv*_i rv*_m rv*_a rv*_c rv*_zicsr rv*_f rv_system rv*_d rv*_v'

# copy the riscv-opcodes to the rust src directory
echo "Copying riscv-opcodes to $RUST_SRC_DIR"
cp $OPCODES_DIR/isa.rs $RUST_SRC_DIR/isa.rs
cp $OPCODES_DIR/isa_consts.rs $RUST_SRC_DIR/isa_consts.rs

echo "Done"