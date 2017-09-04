# Copyright 2016 Amazon.com, Inc. or its
# affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may not
# use this file except in compliance with the License. A copy of the License
# is located at
#
#    http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is distributed
# on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.

import argparse
import json
import os
import sys
from collections import defaultdict
# Subprocess is used to address
# https://github.com/tomerfiliba/plumbum/issues/295
from subprocess import Popen, PIPE

from plumbum import local

PY_FILES = (".py",)

# Prepare global git cmd
git = local["git"]

# commands
cmd_pylint = [
    'pylint',
    '-rn',
    '--disable=C0103',
    '--msg-template="{path}@@{line}@@"[PYLINT] [{msg_id}] ({symbol}) {msg}" ']
cmd_flake8 = [
    'flake8',
    '--format=%(path)s@@%(row)d@@[FLAKE8] [%(code)s] %(text)s']


class GerritCheckException(RuntimeError):
    pass


def extract_files_for_commit(rev, branch):
    """
    :return: A list of files that where modified in revision 'rev'
    """
    diff = Popen(["git", "diff-tree", "--no-commit-id", "--name-only", "-r",
                  "..".join([rev, branch])], stdout=PIPE, universal_newlines=True)

    out, err = diff.communicate()

    if err:
        raise GerritCheckException("Could not run diff on current revision. "
                                   "Make sure that the current revision has a "
                                   "parent: %s" % err)
    return [f.strip() for f in out.splitlines() if len(f)]


def filter_files(files, suffix=PY_FILES):
    result = []
    for f in files:
        if f.endswith(suffix) and os.path.exists(f):
            result.append(f)
    return result


def line_part_of_commit(file, line, commit):
    """Helper function that returns true if a particular `line` in a
    particular `file` was last changed in `commit`."""
    line_val = git("blame", "-l", "-L{0},{0}".format(line), file)
    return line_val.split(" ", 1)[0] == commit


def run_cmd(check_cmd):
    cmd = Popen(check_cmd, cwd=os.getcwd(), shell=False,
                stdout=PIPE, universal_newlines=True)

    out, err = cmd.communicate()

    if err:
        raise GerritCheckException(
            "Could not run '%s' in current directory. %s" %
            (check_cmd, err))
    return [f.strip() for f in out.splitlines() if len(f)]


def py_checks_on_files(files, commit):
    """ Runs flake8 on the files to report style guide violations.
    """

    # We need to redirect stdout while generating the JSON to avoid spilling
    # messages to the user.
    old_stdout = sys.stdout
    sys.stdout = open("/dev/null", "w")
    review = {}
    reference = {}
    report = []
    report.extend(run_cmd(cmd_flake8 + files))
    report.extend(run_cmd(cmd_pylint + files))

    for file in filter_files(files, (".py",)):
        review.setdefault('comments', defaultdict(list))
        for line in report:
            if '@@' not in line:
                continue
            file_name, line_number, text = line.split('@@')
            if file != file_name:
                continue
            # if not line_part_of_commit(file, line_number, commit): continue
            message = " " + text.strip('"')
            try:
                message = reference['comments'][file][
                    line_number] + "\n " + message
            except KeyError:
                message = message
            reference.setdefault('comments', {}).setdefault(
                file, {}).update({line_number: message})
            review["comments"][file].append({
                "path": file,
                "line": line_number,
                "message": message
            })
    if "comments" in review and len(review["comments"]):
        review["message"] = "[CHECKS] Some issues found."
    else:
        review["message"] = "[CHECKS] No issues found. OK"
    sys.stdout = old_stdout
    return json.dumps(review)


def submit_review(change, user, host, data, port=22):
    """Uses the data as input to submit a new review."""
    remote = local["ssh"]["{0}@{1}:{2}".format(user, host, port)]
    (local["cat"] << data | remote["gerrit", "review", change, "--json"])()


# Mapping a particular checking function to a tool name
CHECKER_MAPPING = {
    "flake8": py_checks_on_files
}


def main():
    parser = argparse.ArgumentParser(
        description=("Execute code analysis and report results locally "
                     "or to gerrit"),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument("-g", "--gerrit-host", help="Gerrit host")
    parser.add_argument("-u", "--user", help="Username", default="jenkins")
    parser.add_argument("-p", "--port", help="SSH port Gerrit listens on",
                        default=22)
    parser.add_argument("-c", "--commit",
                        help="Git Hash of the commit to check",
                        default="HEAD")
    parser.add_argument("-t", "--tool", help="Which validation to run",
                        choices=CHECKER_MAPPING.keys(), action="append",
                        required=True)
    parser.add_argument("-l", "--local", action="store_true", default=False,
                        help=("Display output locally instead "
                              "of submitting it to Gerrit"))
    parser.add_argument("-b", "--branch_name",
                        required=True, help="Branch Name")

    args = parser.parse_args()

    modified_files = extract_files_for_commit(args.commit, args.branch_name)

    current_hash = git("rev-parse", args.commit).strip()
    for t in args.tool:
        result = CHECKER_MAPPING[t](modified_files, current_hash)
        if args.local:
            print(json.dumps(json.loads(result)))
        else:
            submit_review(args.commit, args.user,
                          args.gerrit_host, result, args.port)


if __name__ == "__main__":
    main()
