DeepDi is a deep learning-based disassembler that produces x86 disassembly results accurately and efficiently. It can be easily set up in Docker. To build and run DeepDi in Docker:

1. Run `docker build -t DeepDi .` (or `docker build -t DeepDi -f Dockerfile-gpu .` for GPU support).
2. Run `docker run --rm -it DeepDi`. Add `--gpus all` to the docker command line if you intend to use GPU.
3. Usage: `python3 DeepDi.py [--gpu] --path BINARY_PATH`.

`DeepDi.py` is designed to work together with our Ghidra plugin. It will generate two files: `BINARY_PATH{_inst.txt}` and `BINARY_PATH{_func.txt}` with instruction and function addresses, respectively. The Ghidra plugin will create instructions and functions from these files. 

Note that the default batch size is `1024 * 512` for a GPU with 12 GB memory. If you have a smaller VRAM, please lower the batch size. 



`DeepDi.py` provides a wrapper for low-level APIs. Please see [API.md](API.md) for the details of the low-level APIs.



To use the Ghidra plugin, first copy `deepdi_ghidra.java` to the Ghidra plugin folder, e.g., `~/ghidra_scripts`. After loading the file for analysis, do not run Ghidra's analyzer. Open Ghidra Script Manager and run `deepdi_ghidra.java`. 
