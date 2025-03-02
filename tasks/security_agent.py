import datetime
import os
import shutil
import sys
import tempfile

from invoke import task

from .build_tags import get_default_build_tags
from .go import generate, golangci_lint, staticcheck, vet
from .utils import (
    REPO_PATH,
    bin_name,
    bundle_files,
    generate_config,
    get_build_flags,
    get_git_branch_name,
    get_git_commit,
    get_go_version,
    get_gopath,
    get_version,
    get_version_numeric_only,
)

BIN_DIR = os.path.join(".", "bin")
BIN_PATH = os.path.join(BIN_DIR, "security-agent", bin_name("security-agent", android=False))
GIMME_ENV_VARS = ['GOROOT', 'PATH']
CLANG_EXE_CMD = "clang {flags} '{c_file}' -o '{out_file}'"


def get_go_env(ctx, go_version):
    goenv = {}
    if go_version:
        lines = ctx.run(f"gimme {go_version}").stdout.split("\n")
        for line in lines:
            for env_var in GIMME_ENV_VARS:
                if env_var in line:
                    goenv[env_var] = line[line.find(env_var) + len(env_var) + 1 : -1].strip('\'\"')

    # extend PATH from gimme with the one from get_build_flags
    if "PATH" in os.environ and "PATH" in goenv:
        goenv["PATH"] += ":" + os.environ["PATH"]

    return goenv


@task
def build(
    ctx,
    race=False,
    go_version=None,
    incremental_build=False,
    major_version='7',
    # arch is never used here; we keep it to have a
    # consistent CLI on the build task for all agents.
    arch="x64",  # noqa: U100
    go_mod="mod",
    skip_assets=False,
):
    """
    Build the security agent
    """
    ldflags, gcflags, env = get_build_flags(ctx, major_version=major_version, python_runtimes='3')

    # generate windows resources
    if sys.platform == 'win32':
        windres_target = "pe-x86-64"
        if arch == "x86":
            env["GOARCH"] = "386"
            windres_target = "pe-i386"

        ver = get_version_numeric_only(ctx, major_version=major_version)
        maj_ver, min_ver, patch_ver = ver.split(".")

        ctx.run(
            f"windmc --target {windres_target}  -r cmd/security-agent/windows_resources cmd/security-agent/windows_resources/security-agent-msg.mc"
        )
        ctx.run(
            f"windres --define MAJ_VER={maj_ver} --define MIN_VER={min_ver} --define PATCH_VER={patch_ver} -i cmd/security-agent/windows_resources/security-agent.rc --target {windres_target} -O coff -o cmd/security-agent/rsrc.syso"
        )

    # TODO use pkg/version for this
    main = "main."
    ld_vars = {
        "Version": get_version(ctx, major_version=major_version),
        "GoVersion": get_go_version(),
        "GitBranch": get_git_branch_name(),
        "GitCommit": get_git_commit(),
        "BuildDate": datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
    }

    goenv = {}
    if go_version:
        lines = ctx.run(f"gimme {go_version}").stdout.split("\n")
        for line in lines:
            for env_var in GIMME_ENV_VARS:
                if env_var in line:
                    goenv[env_var] = line[line.find(env_var) + len(env_var) + 1 : -1].strip('\'\"')
        ld_vars["GoVersion"] = go_version

    # Generating go source from templates by running go generate on ./pkg/status
    generate(ctx)

    # extend PATH from gimme with the one from get_build_flags
    if "PATH" in os.environ and "PATH" in goenv:
        goenv["PATH"] += ":" + os.environ["PATH"]
    env.update(goenv)

    ldflags += ' '.join([f"-X '{main + key}={value}'" for key, value in ld_vars.items()])
    build_tags = get_default_build_tags(
        build="security-agent"
    )  # TODO/FIXME: Arch not passed to preserve build tags. Should this be fixed?

    # TODO static option
    cmd = 'go build -mod={go_mod} {race_opt} {build_type} -tags "{go_build_tags}" '
    cmd += '-o {agent_bin} -gcflags="{gcflags}" -ldflags="{ldflags}" {REPO_PATH}/cmd/security-agent'

    args = {
        "go_mod": go_mod,
        "race_opt": "-race" if race else "",
        "build_type": "" if incremental_build else "-a",
        "go_build_tags": " ".join(build_tags),
        "agent_bin": BIN_PATH,
        "gcflags": gcflags,
        "ldflags": ldflags,
        "REPO_PATH": REPO_PATH,
    }

    ctx.run(cmd.format(**args), env=env)

    if not skip_assets:
        dist_folder = os.path.join(BIN_DIR, "agent", "dist")
        generate_config(ctx, build_type="security-agent", output_file="./cmd/agent/dist/security-agent.yaml", env=env)
        shutil.copy("./cmd/agent/dist/security-agent.yaml", os.path.join(dist_folder, "security-agent.yaml"))


@task()
def gen_mocks(ctx):
    """
    Generate mocks.
    """

    interfaces = [
        "AuditClient",
        "Builder",
        "Clients",
        "Configuration",
        "DockerClient",
        "Env",
        "Evaluatable",
        "Iterator",
        "KubeClient",
        "RegoConfiguration",
        "Reporter",
        "Scheduler",
    ]

    interface_regex = "|".join(f"^{i}\\$" for i in interfaces)

    with ctx.cd("./pkg/compliance"):
        ctx.run(f"mockery --case snake -r --name=\"{interface_regex}\"")


@task
def run_functional_tests(ctx, testsuite, verbose=False, testflags=''):
    cmd = '{testsuite} {verbose_opt} {testflags}'
    if os.getuid() != 0:
        cmd = 'sudo -E PATH={path} ' + cmd

    args = {
        "testsuite": testsuite,
        "verbose_opt": "-test.v" if verbose else "",
        "testflags": testflags,
        "path": os.environ['PATH'],
    }

    ctx.run(cmd.format(**args))


def build_go_syscall_tester(ctx, build_dir):
    syscall_tester_go_dir = os.path.join(".", "pkg", "security", "tests", "syscall_tester", "go")
    syscall_tester_exe_file = os.path.join(build_dir, "syscall_go_tester")
    ctx.run(f"go build -o {syscall_tester_exe_file} -tags syscalltesters {syscall_tester_go_dir}/syscall_go_tester.go ")
    return syscall_tester_exe_file


def build_syscall_x86_tester(ctx, build_dir, static=True):
    syscall_tester_c_dir = os.path.join(".", "pkg", "security", "tests", "syscall_tester", "c")
    syscall_tester_c_file = os.path.join(syscall_tester_c_dir, "syscall_x86_tester.c")
    syscall_tester_exe_file = os.path.join(build_dir, "syscall_x86_tester")

    flags = '-m32'
    if static:
        flags += ' -static'
    ctx.run(CLANG_EXE_CMD.format(flags=flags, c_file=syscall_tester_c_file, out_file=syscall_tester_exe_file))
    return syscall_tester_exe_file


def build_syscall_tester(ctx, build_dir, static=True):
    syscall_tester_c_dir = os.path.join(".", "pkg", "security", "tests", "syscall_tester", "c")
    syscall_tester_c_file = os.path.join(syscall_tester_c_dir, "syscall_tester.c")
    syscall_tester_exe_file = os.path.join(build_dir, "syscall_tester")

    flags = ''
    if static:
        flags += ' -static'
    ctx.run(CLANG_EXE_CMD.format(flags=flags, c_file=syscall_tester_c_file, out_file=syscall_tester_exe_file))
    return syscall_tester_exe_file


@task
def build_embed_syscall_tester(ctx, static=True):
    syscall_tester_bin = build_syscall_tester(ctx, os.path.join(".", "bin"), static=static)
    syscall_x86_tester_bin = build_syscall_x86_tester(ctx, os.path.join(".", "bin"), static=static)
    syscall_go_tester_bin = build_go_syscall_tester(ctx, os.path.join(".", "bin"))
    bundle_files(
        ctx,
        [syscall_tester_bin, syscall_x86_tester_bin, syscall_go_tester_bin],
        "bin",
        "pkg/security/tests/syscall_tester/bindata.go",
        "syscall_tester",
        "functionaltests",
        False,
    )


@task
def build_functional_tests(
    ctx,
    output='pkg/security/tests/testsuite',
    go_version=None,
    arch="x64",
    major_version='7',
    build_tags='functionaltests',
    build_flags='',
    bundle_ebpf=True,
    static=False,
    skip_linters=False,
):
    if not skip_linters:
        targets = ['./pkg/security/tests']
        vet(ctx, targets=targets, build_tags=[build_tags], arch=arch)
        golangci_lint(ctx, targets=targets, build_tags=[build_tags], arch=arch)
        staticcheck(ctx, targets=targets, build_tags=[build_tags], arch=arch)

    ldflags, gcflags, env = get_build_flags(ctx, major_version=major_version)

    goenv = get_go_env(ctx, go_version)
    env.update(goenv)

    env["CGO_ENABLED"] = "1"
    if arch == "x86":
        env["GOARCH"] = "386"

    build_tags = "linux_bpf," + build_tags
    if bundle_ebpf:
        build_tags = "ebpf_bindata," + build_tags

    if static:
        ldflags += '-extldflags "-static"'
        build_tags += ',osusergo,netgo'

    cmd = 'go test -mod=mod -tags {build_tags} -ldflags="{ldflags}" -c -o {output} '
    cmd += '{build_flags} {repo_path}/pkg/security/tests'

    args = {
        "output": output,
        "ldflags": ldflags,
        "build_flags": build_flags,
        "build_tags": build_tags,
        "repo_path": REPO_PATH,
    }

    ctx.run(cmd.format(**args), env=env)


@task
def build_stress_tests(
    ctx,
    output='pkg/security/tests/stresssuite',
    go_version=None,
    arch="x64",
    major_version='7',
    bundle_ebpf=True,
    skip_linters=False,
):
    build_functional_tests(
        ctx,
        output=output,
        go_version=go_version,
        arch=arch,
        major_version=major_version,
        build_tags='stresstests',
        bundle_ebpf=bundle_ebpf,
        skip_linters=skip_linters,
    )


@task
def stress_tests(
    ctx,
    verbose=False,
    go_version=None,
    arch="x64",
    major_version='7',
    output='pkg/security/tests/stresssuite',
    bundle_ebpf=True,
    testflags='',
    skip_linters=False,
):
    build_stress_tests(
        ctx,
        go_version=go_version,
        arch=arch,
        major_version=major_version,
        output=output,
        bundle_ebpf=bundle_ebpf,
        skip_linters=skip_linters,
    )

    run_functional_tests(
        ctx,
        testsuite=output,
        verbose=verbose,
        testflags=testflags,
    )


@task
def functional_tests(
    ctx,
    verbose=False,
    go_version=None,
    arch="x64",
    major_version='7',
    output='pkg/security/tests/testsuite',
    bundle_ebpf=True,
    testflags='',
    skip_linters=False,
):
    build_functional_tests(
        ctx,
        go_version=go_version,
        arch=arch,
        major_version=major_version,
        output=output,
        bundle_ebpf=bundle_ebpf,
        skip_linters=skip_linters,
    )

    run_functional_tests(
        ctx,
        testsuite=output,
        verbose=verbose,
        testflags=testflags,
    )


@task
def kitchen_functional_tests(
    ctx,
    verbose=False,
    go_version=None,
    major_version='7',
    build_tests=False,
    testflags='',
):
    if build_tests:
        functional_tests(
            ctx,
            verbose=verbose,
            go_version=go_version,
            arch="x64",
            major_version=major_version,
            output="test/kitchen/site-cookbooks/dd-security-agent-check/files/testsuite",
            testflags=testflags,
        )

        functional_tests(
            ctx,
            verbose=verbose,
            go_version=go_version,
            major_version=major_version,
            output="test/kitchen/site-cookbooks/dd-security-agent-check/files/testsuite32",
            arch="x86",
            testflags=testflags,
        )

    kitchen_dir = os.path.join("test", "kitchen")
    shutil.copy(
        os.path.join(kitchen_dir, "kitchen-vagrant-security-agent.yml"), os.path.join(kitchen_dir, "kitchen.yml")
    )

    with ctx.cd(kitchen_dir):
        ctx.run("kitchen test")


@task
def docker_functional_tests(
    ctx,
    verbose=False,
    go_version=None,
    arch="x64",
    major_version='7',
    testflags='',
    static=False,
    skip_linters=False,
):
    build_functional_tests(
        ctx,
        go_version=go_version,
        arch=arch,
        major_version=major_version,
        output="pkg/security/tests/testsuite",
        bundle_ebpf=True,
        static=static,
        skip_linters=skip_linters,
    )

    dockerfile = """
FROM debian:bullseye

RUN dpkg --add-architecture i386

RUN apt-get update -y \
    && apt-get install -y --no-install-recommends xfsprogs libc6:i386 \
    && rm -rf /var/lib/apt/lists/*
    """

    docker_image_tag_name = "docker-functional-tests"

    # build docker image
    with tempfile.TemporaryDirectory() as temp_dir:
        print("Create tmp dir:", temp_dir)
        with open(os.path.join(temp_dir, "Dockerfile"), "w") as f:
            f.write(dockerfile)

        cmd = 'docker build {docker_file_ctx} --tag {image_tag}'
        ctx.run(cmd.format(**{"docker_file_ctx": temp_dir, "image_tag": docker_image_tag_name}))

    container_name = 'security-agent-tests'
    capabilities = ['SYS_ADMIN', 'SYS_RESOURCE', 'SYS_PTRACE', 'NET_ADMIN', 'IPC_LOCK', 'ALL']

    cmd = 'docker run --name {container_name} {caps} --privileged -d --pid=host '
    cmd += '-v /dev:/dev '
    cmd += '-v /proc:/host/proc -e HOST_PROC=/host/proc '
    cmd += '-v /:/host/root -e HOST_ROOT=/host/root '
    cmd += '-v /etc:/host/etc -e HOST_ETC=/host/etc '
    cmd += '-v {GOPATH}/src/{REPO_PATH}/pkg/security/tests:/tests {image_tag} sleep 3600'

    args = {
        "GOPATH": get_gopath(ctx),
        "REPO_PATH": REPO_PATH,
        "container_name": container_name,
        "caps": ' '.join(['--cap-add ' + cap for cap in capabilities]),
        "image_tag": docker_image_tag_name + ":latest",
    }

    ctx.run(cmd.format(**args))

    cmd = 'docker exec {container_name} mount -t debugfs none /sys/kernel/debug'
    ctx.run(cmd.format(**args))

    cmd = 'docker exec {container_name} /tests/testsuite --env docker {testflags}'
    if verbose:
        cmd += ' -test.v'
    try:
        ctx.run(cmd.format(testflags=testflags, **args))
    finally:
        cmd = 'docker rm -f {container_name}'
        ctx.run(cmd.format(**args))


@task
def generate_cws_documentation(ctx, go_generate=False):
    if go_generate:
        cws_go_generate(ctx)

    # secl docs
    ctx.run(
        "python3 ./docs/cloud-workload-security/scripts/secl-doc-gen.py --input ./docs/cloud-workload-security/secl.json --output ./docs/cloud-workload-security/agent_expressions.md"
    )
    # backend event docs
    ctx.run(
        "python3 ./docs/cloud-workload-security/scripts/backend-doc-gen.py --input ./docs/cloud-workload-security/backend.schema.json --output ./docs/cloud-workload-security/backend.md"
    )


@task
def cws_go_generate(ctx):
    with ctx.cd("./pkg/security/secl"):
        ctx.run("go generate ./...")
    ctx.run("go generate ./pkg/security/...")
