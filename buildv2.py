#!/usr/bin/env python

"""The kernelci builder script."""

# pylint: disable=invalid-name
# pylint: disable=broad-except

import ConfigParser
import argparse
import fnmatch
import io
import json
import logging
import multiprocessing
import os
import platform
import re
import requests
import shutil
import stat
import subprocess
import sys
import tempfile
import time

from urlparse import urljoin


BUILD_CONFIG_FILE = "~/.buildpy.cfg"
BUILD_LOG_FILE_NAME = "build.log"
CONFIG_PATH = "arch/{0.arch:s}/configs/{1:s}"
BUILD_UPLOAD_PATH = \
    "{0.job:s}/{0.git_describe:s}/{0.arch:s}-{0.defconfig_full:s}"
KBUILD_OUTPUT_PREFIX = "build"
KBUILD_OUTPUT = KBUILD_OUTPUT_PREFIX
_, KCONFIG_TMPFILE = tempfile.mkstemp(prefix="kconfig-")

# How many times to retry API actions.
SEND_RETRIES = 3

# List of architectures on their cross-compiler.
CROSS_COMPILERS = {
    "arm": "arm-linux-gnueabi-",
    "arm64": "aarch64-linux-gnu-",
    "i386": None,
    "x86": None,
    "x86_64": None,
}

# Default build architecture.
DEFAULT_ARCH = "arm"
# Default cross-compiler.
CROSS_COMPILE = CROSS_COMPILERS[DEFAULT_ARCH]

# List of environment variable that will be checked.
# Names are converted to upper case when checking their presence.
ENV_VARIABLES = [
    "arch",
    "cross_compile",
    "kbuild_output",
    "ccache_disable",
    "ccache_dir",
    "git_describe",
    "tree_name"
]

# Values to take out of a git repository, with the command necessary to extract
# them.
GIT_VARIABLES_AND_COMMANDS = {
    "git_commit": r"git log -n1 --format=%H",
    "git_url": "git config --get remote.origin.url | cat",
    "git_branch": "git rev-parse --abbrev-ref HEAD",
    "git_describe_v": r"git describe --match=v[34]\*",
    "git_describe": "git describe"
}

# Modules tarball creation command.
MODULES_TAR_CMD = "(cd {:s}; tar -Jcf {:s} lib/modules)"

# Config merge script command.
CONFIG_MERGE_CMD = (
    "scripts/kconfig/merge_config.sh -O {0.kbuild_output:s} {1:s} {2:s} >"
    " /dev/null 2>&1"
)

logger = logging.getLogger("kernelci-builder")
handler = logging.StreamHandler()


class BuildConfig(object):
    """An object to hold build configuration parameters."""
    def __init__(self):
        # Not all of the configuration attributes are listed.
        self.build_log = None
        self.build_result = "PASS"
        self.build_time = 0
        self.debug = False
        self.install = False
        self.modules = False
        self.publish = False
        self.tree_name = None


def check_proc_output(cmd, shell=True):
    """Run a shell command in a subprocess and return its output."""
    ret_val = None
    try:
        ret_val = subprocess.check_output(cmd, shell=shell)
    except subprocess.CalledProcessError:
        logger.error("Error running command: %s", cmd)
        sys.exit(1)
    return ret_val


def do_make(build_cfg, target=None, log=False, cmd_vars=None):
    """Execute the make command.

    :param build_cfg: The BuildConfig object.
    :type build_cfg: object
    :param target: The target to make.
    :type target: str
    :param log: If to log the make output. Default to false.
    :type log: bool
    :param cmd_vars: List of variable names to add to the command line string.
    :type cmd_vars: list
    """
    make_args = "-j{0.make_threads:d} -k".format(build_cfg)

    if build_cfg.quiet:
        make_args += " -s"

    make_args += " ARCH={0.arch:s}".format(build_cfg)

    if build_cfg.cross_compile:
        make_args += " CROSS_COMPILE={0.cross_compile:s}".format(build_cfg)

    if build_cfg.ccache:
        prefix = ""
        if build_cfg.cross_compile:
            prefix = build_cfg.cross_compile
        make_args += " CC=\"ccache {:s}gcc\"".format(prefix)

    if build_cfg.kbuild_output:
        make_args += " O={0.kbuild_output:s}".format(build_cfg)

    if target:
        make_args += target

    make_vars = ""
    if cmd_vars:
        def _create_var_string():
            """Create the key=val string for the command line."""
            for var in cmd_vars:
                yield "{0:s}={1:s}".format(
                    var.upper(), getattr(build_cfg, var))

        make_vars = " ".join(_create_var_string())

    make_cmd = "make {0:s} {1:s}".format(make_vars.strip(), make_args.strip())
    logger.info("Make command is: %s", make_cmd)

    make_out = None
    if log:
        make_out = io.open(build_cfg.build_log, mode="a")
        make_out.write(u"\n#\n# {:s}\n#\n".format(make_cmd))

    proc = subprocess.Popen(
        make_cmd, shell=True, stdout=make_out, stderr=subprocess.STDOUT)

    proc.communicate()
    return proc.wait()


def prepare_build(build_cfg):
    """Run all build operations.

    :param build_cfg: The BuildConfig object.
    :type build_cfg: object
    :return The status of the ran commands.
    """
    frag_names = build_cfg.frag_names
    defconfig = build_cfg.defconfig
    dot_config = build_cfg.dot_config

    logger.debug("Working defconfig: %s", defconfig)
    logger.debug("Working config fragments: %s", frag_names)

    build_cfg.kconfig_frag = None
    if any([defconfig, frag_names]):
        base = ""

        if defconfig:
            do_make(build_cfg, target=defconfig, log=True)
            base = dot_config

        if frag_names:
            config_frag = os.path.join(
                build_cfg.kbuild_output,
                "frag-{:s}.config".format("+".join(frag_names)))

            build_cfg.kconfig_frag = config_frag

            shutil.copy(KCONFIG_TMPFILE, config_frag)
            os.chmod(
                config_frag,
                stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)

            cmd = CONFIG_MERGE_CMD.format(build_cfg, base, config_frag)
            logger.debug("Config merge command is: %s", cmd)

            subprocess.call(cmd, shell=True)
    elif os.path.exists(dot_config):
        logger.info("Re-using .config: %s", dot_config)
        defconfig = "existing"
    else:
        logger.error("Missing kernel config, aborting.")
        sys.exit(0)

    build_cfg.defconfig = defconfig

    result = 0
    if build_cfg.target:
        for target in build_cfg.target:
            result |= do_make(build_cfg, target=target, log=True)
    else:
        result |= do_make(build_cfg, log=True)

    modules = False
    if result == 0:
        if all([not build_cfg.target, os.path.exists(dot_config)]):
            with io.open(dot_config, mode="r") as conf:
                for line in conf:
                    line = line.strip()
                    if line == "CONFIG_MODULES=y":
                        modules = True
                        break

    build_cfg.modules = modules

    if build_cfg.modules:
        logger.debug("Making modules...")

        result |= do_make(build_cfg, target="modules", log=True)

        logger.debug("Installing modules...")

        build_cfg.install_mod_path = tmp_mod_dir = tempfile.mkdtemp()
        do_make(
            build_cfg, target="modules_install", cmd_vars=["install_mod_path"])

        build_cfg.modules_tarball = modules_tarball = "modules.tar.xz"
        cmd = MODULES_TAR_CMD.format(tmp_mod_dir, modules_tarball)

        result |= subprocess.call(cmd, shell=True)

    return result


def complete_build(build_cfg):
    """Complete the build.

    Copy files in the install location, collect data.

    :param build_cfg: The BuildConfig object.
    """
    boot_dir = "{0.kbuild_output:s}/arch/{0.arch:s}/boot".format(build_cfg)
    text_offset = -1
    system_map = os.path.join(build_cfg.kbuild_output, "System.map")
    kimage_file = None
    kimages = []
    dtb_dest = None

    install_path = \
        os.path.join(os.getcwd(), "_install_", build_cfg.git_describe)

    if build_cfg.defconfig:
        build_cfg.defconfig_full = build_cfg.defconfig
        install_path = os.path.join(
            install_path, "{0.arch:s}-{0.defconfig:s}".format(build_cfg))

    if build_cfg.frag_names:
        fragments = "+{:s}".format("+".join(build_cfg.frag_names))
        install_path += fragments
        build_cfg.defconfig_full += fragments

    build_cfg.install_path = install_path
    logger.debug("Install path is: %s", install_path)

    if not os.path.exists(install_path):
        os.makedirs(install_path)

    if os.path.exists(system_map):
        virt_text = check_proc_output(
            "grep \" _text\" {:s}".format(system_map)).split()[0]
        # phys: cap at 1G
        text_offset = int(virt_text, 16) & (1 << 30) - 1
        shutil.copy(system_map, install_path)
    else:
        system_map = None
        text_offset = None

    build_cfg.system_map = system_map
    build_cfg.text_offset = text_offset

    dot_config_installed = os.path.join(install_path, "kernel.config")
    shutil.copy(build_cfg.dot_config, dot_config_installed)
    build_cfg.dot_config_installed = dot_config_installed

    shutil.copy(build_cfg.build_log, install_path)
    if build_cfg.kconfig_frag:
        shutil.copy(build_cfg.kconfig_frag, install_path)

    # Patterns for matching kernel images by architecture
    if build_cfg.arch == "arm":
        patterns = ["zImage", "xipImage"]
    elif build_cfg.arch == "arm64":
        patterns = ["Image"]
    else:
        # TODO: Fix this assumption. ARCH != ARM* == x86
        patterns = ["bzImage"]

    for pattern in patterns:
        for root, _, filenames in os.walk(boot_dir):
            for filename in fnmatch.filter(filenames, pattern):
                kimages.append(os.path.join(root, filename))
                shutil.copy(os.path.join(root, filename), install_path)

    if os.path.isfile(os.path.join(build_cfg.kbuild_output, "vmlinux")):
        shutil.copy(
            os.path.join(build_cfg.kbuild_output, "vmlinux"), install_path)
        build_cfg.vmlinux_file = "vmlinux"

    if len(kimages) == 1:
        kimage_file = kimages[0]
    elif len(kimages) > 1:
        for kimage in kimages:
            if os.path.basename(kimage).startswith("z"):
                kimage_file = kimage

    build_cfg.kimage_file = kimage_file

    for root, _, filenames in os.walk(os.path.join(boot_dir, "dts")):
        for filename in fnmatch.filter(filenames, "*.dtb"):
            # Found a dtb
            dtb = os.path.join(root, filename)
            dtb_dest = os.path.join(install_path, "dtbs")
            # Check if the dtb exists in a subdirectory
            if root.split(os.path.sep)[-1] != "dts":
                dest = os.path.join(
                    install_path, "dtbs", root.split(os.path.sep)[-1])
            else:
                dest = os.path.join(install_path, "dtbs")

            if not os.path.exists(dest):
                os.makedirs(dest)
            # Copy the dtb
            shutil.copy(dtb, dest)

    build_cfg.dtb_dest = dtb_dest

    if all([build_cfg.modules, build_cfg.modules_tarball]):
        shutil.copy(
            os.path.join(
                build_cfg.install_mod_path, build_cfg.modules_tarball),
            install_path)
        shutil.rmtree(build_cfg.install_mod_path)


def create_build_json_data(build_cfg):
    """Create the JSON data structure to be sent.

    :param build_cfg: The BuildConfig object.
    :return The JSON data as a dictionary.
    """
    install_path = build_cfg.install_path

    build_data = {}

    if build_cfg.tree_name:
        build_data["job"] = build_cfg.tree_name

    build_data["arch"] = build_cfg.arch
    build_data["defconfig"] = build_cfg.defconfig
    build_data["defconfig_full"] = build_cfg.defconfig_full
    build_data["kernel"] = build_cfg.git_describe

    build_data["build_result"] = build_cfg.build_result
    build_data["build_time"] = round(build_cfg.build_time, 2)
    build_data["compiler_version"] = build_cfg.gcc_version
    build_data["cross_compile"] = build_cfg.cross_compile
    build_data["git_branch"] = build_cfg.git_branch
    build_data["git_commit"] = build_cfg.git_commit
    build_data["git_describe"] = build_cfg.git_describe
    build_data["git_describe_v"] = build_cfg.git_describe_v
    build_data["git_url"] = build_cfg.git_url

    if build_cfg.kconfig_frag:
        build_data["kconfig_fragments"] = \
            os.path.basename(build_cfg.kconfig_frag)

    if build_cfg.kimage_file:
        k_image = os.path.basename(build_cfg.kimage_file)
        build_data["kernel_image"] = k_image
        build_data["kernel_image_size"] = \
            os.stat(os.path.join(install_path, k_image)).st_size

    if build_cfg.dot_config_installed:
        k_config = os.path.basename(build_cfg.dot_config_installed)
        build_data["kernel_config"] = k_config
        build_data["kernel_config_size"] = \
            os.stat(os.path.join(install_path, k_config)).st_size

    if build_cfg.system_map:
        s_map = os.path.basename(build_cfg.system_map)
        build_data["system_map"] = s_map
        build_data["system_map_size"] = \
            os.stat(os.path.join(install_path, s_map)).st_size

    if build_cfg.text_offset:
        build_data["text_offset"] = "0x{:08x}".format(build_cfg.text_offset)

    if build_cfg.dtb_dest:
        # TODO: parse dtb_dir
        build_data["dtb_dir"] = os.path.basename(build_cfg.dtb_dest)

    if all([build_cfg.modules, build_cfg.modules_tarball]):
        build_data["modules"] = build_cfg.modules_tarball
        build_data["modules_size"] = \
            os.stat(os.path.join(
                install_path, build_cfg.modules_tarball)).st_size

    if build_cfg.build_log:
        b_log = os.path.basename(build_cfg.build_log)
        build_data["build_log"] = b_log
        build_data["build_log_size"] = \
            os.stat(os.path.join(install_path, b_log)).st_size

    if build_cfg.vmlinux_file:
        build_data["vmlinux_file"] = build_cfg.vmlinux_file
        # TODO: extract also the ELF sections.
        build_data["vmlinux_file_size"] = \
            os.stat(os.path.join(install_path, build_cfg.vmlinux_file)).st_size

    build_data["build_platform"] = platform.uname()

    # TODO: when API changes, we don't need anymore the JSON file.
    json_str = json.dumps(build_data, indent=4, sort_keys=True)
    json_file = os.path.join(install_path, "build.json")
    with io.open(json_file, mode="w") as build:
        build.write(unicode(json_str, "utf-8"))

    logger.debug("Build JSON data: %s", build_data)

    return build_data


def publish_data(build_cfg, base_url, token):
    """Upload artifacts to storage server.

    :param build_cfg: The BuildConfig object.
    :param base_url: The API URL.
    :param token: The API authentication token.
    """
    artifacts = []

    publish_path = BUILD_UPLOAD_PATH.format(build_cfg)
    # TODO: need to add a "late delete" parameters, since we sill need to
    # parse things on the server.
    data = {
        "path": publish_path,
        "job": build_cfg.tree_name,
        "kernel": build_cfg.git_describe,
        "defconfig": build_cfg.defconfig,
        "defconfig_full": build_cfg.defconfig_full,
        "arch": build_cfg.arch
    }
    count = 1

    for root, _, files in os.walk(build_cfg.install_path):
        if count == 1:
            top_dir = root
        for file_name in files:
            name = file_name
            if root != top_dir:
                # Get the relative subdir path.
                subdir = root[len(top_dir) + 1:]
                name = os.path.join(subdir, file_name)
            artifacts.append((
                "file{:d}".format(count),
                (name, io.open(os.path.join(root, file_name), mode="rb")))
            )
            count += 1

    upload_retries = 0
    while upload_retries < SEND_RETRIES:
        response = requests.post(
            urljoin(base_url, "/upload"),
            data=data, headers={"Authorization": token}, files=artifacts)

        status_code = response.status_code
        if status_code == 503:
            logger.info("API server under maintenance, wait and retry...")
            upload_retries += 1
            time.sleep(60 * upload_retries)
        elif any([status_code == 400, status_code == 415, status_code == 422]):
            logger.error("Data sent is not correct (%s)", str(status_code))
            logger.error(response.json())
            break
        elif status_code == 500:
            logger.error("Remote server error")
            logger.error(response.json())
            break
        elif any([status_code == 200, status_code == 202, status_code == 201]):
            logger.info("Artifacts published")
            for publish_result in json.loads(response.content)["result"]:
                logger.info(
                    "{:s}/{:s}".format(
                        publish_path, publish_result["filename"]))
            break
        else:
            logger.info("Request status code is %s", str(status_code))
            break


def trigger_build_import(data, base_url, token):
    """Trigger the import of the build on the API side.

    :param data: The JSON data.
    :param base_url: The API URL.
    :param token: The API authentication token.
    """
    data_get = data.get

    send_data = {
        "arch": data_get("arch"),
        "job": data_get("job"),
        "kernel": data_get("git_describe"),
        "defconfig": data_get("defconfig")
    }

    defconfig_full = data_get("defconfig_full", None)
    if defconfig_full:
        send_data["defconfig_full"] = defconfig_full

    headers = {
        "Authorization": token,
        "Content-Type": "application/json"
    }
    build_url = urljoin(base_url, "/build")

    build_retries = 0
    while build_retries < SEND_RETRIES:
        response = requests.post(
            build_url, data=json.dumps(send_data), headers=headers)

        status_code = response.status_code
        if status_code == 503:
            logger.info("API server under maintenance, wait and retry...")
            build_retries += 1
            time.sleep(60 * build_retries)
        elif any([status_code == 400, status_code == 415, status_code == 422]):
            logger.error("Data sent is not correct (%s)", str(status_code))
            logger.error(response.json())
            break
        elif status_code == 500:
            logger.error("Remote server error")
            logger.error(response.json())
            break
        elif any([status_code == 200, status_code == 202, status_code == 201]):
            logger.info("Request accepted")
            break
        else:
            logger.info("Request status code is %s", str(status_code))
            break


def write_conf_fragment_file(conf):
    """Write a config fragment file into a temporary one."""
    with io.open(KCONFIG_TMPFILE, mode="a") as kfile, \
            io.open(conf, mode="r+b") as conf_file:
        kfile.write(u"\n# fragment from: {:s}\n".format(conf))
        for line in conf_file:
            kfile.write(unicode(line, "utf-8"))


def get_gcc_compiler_version(build_cfg):
    """Extract the gcc compiler version from the environment.

    :param build_cfg: The BuildConfig object.
    :type build_cfg: object
    :return The compiler version string or none.
    """
    logger.debug("Retrieving gcc compiler version...")

    command = "gcc -v 2>&1"
    if build_cfg.cross_compile:
        command = "{0.cross_compile:s}gcc -v 2>&1".format(build_cfg)
    out_version = check_proc_output(command)

    if out_version:
        out_version = out_version.splitlines()[-1]
    else:
        out_version = None

    return out_version


def get_git_repository_values():
    """Extract git values from the repository."""
    logger.debug("Retrieving git values from repository...")
    values = []

    if os.path.exists(".git"):
        for k, v in GIT_VARIABLES_AND_COMMANDS.iteritems():
            values.append((k, check_proc_output(v).strip()))

    return values


def check_and_set_environment(build_cfg):
    """Check and set the build config environment.

    Check the environment variables and set up all the other needed build
    environment parameters.

    :param build_cfg: The BuildConfig object.
    """
    logger.debug("Setting up the build environment...")
    for env_v in ENV_VARIABLES:
        setattr(build_cfg, env_v, os.environ.get(env_v.upper()))

    # Set the job name.
    if build_cfg.tree_name:
        build_cfg.job = build_cfg.tree_name

    if not build_cfg.arch:
        build_cfg.arch = DEFAULT_ARCH

    if not build_cfg.cross_compile:
        if build_cfg.arch in CROSS_COMPILERS.viewkeys():
            build_cfg.cross_compile = CROSS_COMPILERS[build_cfg.arch]

    # ccache available or not.
    if not build_cfg.ccache_disable:
        build_cfg.ccache = check_proc_output("which ccache | cat").strip()

    # Compile cache directory.
    if all([build_cfg.ccache, not build_cfg.ccache_dir]):
        build_cfg.ccache_dir = \
            os.path.join(os.getcwd(), ".ccache-{0.arch:s}".format(build_cfg))

    # Build output directory.
    if not build_cfg.kbuild_output:
        build_cfg.kbuild_output = KBUILD_OUTPUT
    logger.debug("Build output directory is: %s", build_cfg.kbuild_output)

    if not os.path.exists(build_cfg.kbuild_output):
        os.makedirs(build_cfg.kbuild_output)

    # Build log file.
    build_cfg.build_log = \
        os.path.join(build_cfg.kbuild_output, BUILD_LOG_FILE_NAME)

    # Just create the empty build log file or clean it up.
    with io.open(build_cfg.build_log, mode="w"):
        pass

    # The .config file.
    build_cfg.dot_config = os.path.join(build_cfg.kbuild_output, ".config")

    # Compiler version.
    build_cfg.gcc_version = get_gcc_compiler_version(build_cfg)

    # git commit, url, branch and describe.
    for git_var in get_git_repository_values():
        if all([git_var[0] == "git_describe", not build_cfg.git_describe]):
            build_cfg.git_describe = git_var[1]
        elif git_var[0] != "git_describe":
            setattr(build_cfg, git_var[0], git_var[1])

    # Make threads.
    try:
        cpus = multiprocessing.cpu_count()
    except NotImplementedError:
        cpus = 1

    build_cfg.make_threads = cpus + 2

    build_cfg.defconfig = None
    if build_cfg.config:
        build_cfg.frag_names = frag_names = []

        for conf in build_cfg.config:
            defs = conf.split("+")

            for conf in defs:
                if os.path.isfile(CONFIG_PATH.format(build_cfg, conf)):
                    build_cfg.defconfig = conf
                elif any([conf == "defconfig",
                          conf == "tinyconfig",
                          re.match(r"all(\w*)config", conf)]):
                    build_cfg.defconfig = conf
                elif os.path.isfile(conf):
                    write_conf_fragment_file(conf)
                    frag_names.append(
                        os.path.basename(os.path.splitext(conf)[0]))
                elif conf.startswith("CONFIG_"):
                    with io.open(KCONFIG_TMPFILE, mode="a") as kfile:
                        kfile.write(u"{:s}\n".format(conf))
                    frag_names.append(conf)
                else:
                    logger.error(
                        "kconfig file/fragment (%s) does not exist", conf)
                    sys.exit(1)


def main(args):
    """It all starts here."""
    build_cfg = BuildConfig()

    for k, v in vars(args).iteritems():
        setattr(build_cfg, k, v)

    formatter = logging.Formatter("%(message)s")
    if build_cfg.debug:
        logger.setLevel(logging.DEBUG)
        handler.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.CRITICAL)
        handler.setLevel(logging.CRITICAL)

    handler.setFormatter(formatter)
    logger.addHandler(handler)

    # Default umask for file creation.
    os.umask(022)

    check_and_set_environment(build_cfg)

    logger.debug("Starting build...")
    start_time = time.time()

    result = prepare_build(build_cfg)

    build_cfg.build_time = time.time() - start_time
    logger.debug("Build done.")

    build_data = None
    if build_cfg.install:
        if result != 0:
            build_cfg.build_result = "FAIL"

        logger.debug("Completing build...")
        complete_build(build_cfg)

        logger.debug("Preparing JSON data...")
        build_data = create_build_json_data(build_cfg)

    if all([build_cfg.publish, build_cfg.tree_name, build_data]):
        logger.debug("Sending artifacts and data...")
        config = ConfigParser.ConfigParser()
        try:
            logger.debug(
                "Config file %s", os.path.expanduser(BUILD_CONFIG_FILE))

            config.read(os.path.expanduser(BUILD_CONFIG_FILE))
            base_url = config.get(build_cfg.publish, "url")
            token = config.get(build_cfg.publish, "token")

            publish_data(build_cfg, base_url, token)
            trigger_build_import(build_data, base_url, token)
        except Exception, ex:
            logger.error("Unable to load publish API configuration file")
            logger.debug(str(ex))
    elif all([build_cfg.publish, not build_cfg.tree_name]):
        logger.error("TREE_NAME not set, aborting publish step")

    if os.path.exists(KCONFIG_TMPFILE):
        os.unlink(KCONFIG_TMPFILE)

    # Dump the log to stdout if there have been problems.
    if all([result != 0, os.path.exists(build_cfg.build_log)]):
        with io.open(build_cfg.build_log) as log_file:
            for line in log_file:
                logger.info(line)

    return result


if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser(description="Kernel Builder")
    arg_parser.add_argument("-i", dest="install", action="store_true")
    arg_parser.add_argument(
        "-q", "--quiet", dest="quiet", action="store_true", help="Be quiet")
    arg_parser.add_argument(
        "-c", "--config",
        dest="config", help="Kernel config to build", action="append")
    arg_parser.add_argument(
        "-p", "--publish",
        dest="publish", help="Publish configuration section")
    arg_parser.add_argument(
        "-t", "--target", dest="target", help="Make target", action="append")
    arg_parser.add_argument(
        "-d", "--debug", dest="debug", help="Debug output", action="store_true"
    )

    sys.exit(main(arg_parser.parse_args()))
