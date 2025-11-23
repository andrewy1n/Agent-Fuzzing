import os
import subprocess
import sys
import yaml
from pathlib import Path


def load_config(config_path: str) -> dict:
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)


def save_config(config_path: str, config: dict):
    with open(config_path, 'w') as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)

    print(f"Updated config file: {config_path}")


def find_cgc_binary_dir(cgc_cbs_root: Path, binary_name: str) -> Path:
    search_paths = [
        cgc_cbs_root / "cqe-challenges" / binary_name,
        cgc_cbs_root / "examples" / binary_name,
    ]

    for path in search_paths:
        if path.exists() and path.is_dir():
            return path

    raise FileNotFoundError(
        f"Could not find CGC binary '{binary_name}' in cgc-cbs directory. "
        f"Searched in: {', '.join(str(p) for p in search_paths)}"
    )


def build_cgc_binary(cgc_cbs_root: Path, binary_dir: Path, binary_name: str,
                     compiler: str = "gcc", compiler_flags: str = "-O2 -g -fno-omit-frame-pointer") -> Path:
    build_script = cgc_cbs_root / "bin" / "build.sh"

    if not build_script.exists():
        raise FileNotFoundError(f"Build script not found at {build_script}")

    # Change to the binary directory
    original_cwd = os.getcwd()

    try:
        os.chdir(binary_dir)

        cmd = [str(build_script), binary_name, compiler, compiler_flags] 

        print(f"Building {binary_name} in {binary_dir}")
        print(f"Command: {' '.join(cmd)}")

        result = subprocess.run(
            cmd,
            check=True,
            capture_output=True,
            text=True,
            env={**os.environ, 'PATH': f"{cgc_cbs_root}/bin:{os.environ.get('PATH', '')}"}
        )

        print(result.stdout)
        if result.stderr:
            print(result.stderr, file=sys.stderr)

        built_binary = binary_dir / binary_name

        if not built_binary.exists():
            raise FileNotFoundError(f"Build completed but binary not found at {built_binary}")

        print(f"Successfully built {binary_name}")
        return built_binary

    finally:
        os.chdir(original_cwd)


def main():
    config_path = "config.yaml"
    config = load_config(config_path)

    try:
        binary_name = config['target']['cgc_binary']
    except KeyError:
        print("Error: 'target.cgc_binary' not found in config.yaml", file=sys.stderr)
        sys.exit(1)

    print(f"Target CGC binary: {binary_name}")

    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    cgc_cbs_root = project_root / "cgc-cbs"

    if not cgc_cbs_root.exists():
        print(f"Error: cgc-cbs directory not found at {cgc_cbs_root}", file=sys.stderr)
        sys.exit(1)

    try:
        binary_dir = find_cgc_binary_dir(cgc_cbs_root, binary_name)
        print(f"Found binary source at: {binary_dir}")
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        built_binary = build_cgc_binary(
            cgc_cbs_root,
            binary_dir,
            binary_name,
        )
    except subprocess.CalledProcessError as e:
        print(f"Error building binary: {e}", file=sys.stderr)
        if e.stdout:
            print(e.stdout)
        if e.stderr:
            print(e.stderr, file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    config['target']['binary_path'] = built_binary.as_posix()

    save_config(config_path, config)

    print(f"\nBuild complete! Binary available at: {built_binary}")


if __name__ == "__main__":
    main()
