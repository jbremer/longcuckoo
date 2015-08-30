# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import re
import time
import logging
import subprocess
import os.path

from lib.cuckoo.common.abstracts import Machinery
from lib.cuckoo.common.exceptions import CuckooCriticalError
from lib.cuckoo.common.exceptions import CuckooMachineError

log = logging.getLogger(__name__)

class VirtualBox(Machinery):
    """Virtualization layer for VirtualBox."""

    # VM states.
    SAVED = "saved"
    RUNNING = "running"
    POWEROFF = "poweroff"
    ABORTED = "aborted"
    ERROR = "machete"

    def _initialize_check(self):
        """Runs all checks when a machine manager is initialized.
        @raise CuckooMachineError: if VBoxManage is not found.
        """
        # VirtualBox specific checks.
        if not self.options.virtualbox.path:
            raise CuckooCriticalError("VirtualBox VBoxManage path missing, "
                                      "please add it to the config file")
        if not os.path.exists(self.options.virtualbox.path):
            raise CuckooCriticalError("VirtualBox VBoxManage not found at "
                                      "specified path \"%s\"" %
                                      self.options.virtualbox.path)

        # Base checks.
        super(VirtualBox, self)._initialize_check()

    def _vminfo(self, label):
        """Fetch the state of this Virtual Machine into a dictionary."""
        try:
            output = subprocess.check_output([self.options.virtualbox.path,
                                              "showvminfo", label,
                                              "--machinereadable"])
        except subprocess.CalledProcessError as e:
            log.warning("Error obtaining Virtual Machine state: %s -> %s",
                        label, e)
            return {}

        ret = {}
        for line in output.split("\n"):
            if "=" not in line:
                continue

            # Extract each key/value pair and remove leading/ending quotes.
            key, value = line.split("=", 1)
            ret[key.strip('"')] = value.strip('"')
        return ret

    def start(self, label, revert=True):
        """Start a virtual machine.
        @param label: virtual machine name.
        @raise CuckooMachineError: if unable to start.
        """
        log.debug("Starting vm %s" % label)

        if self._status(label) == self.RUNNING:
            raise CuckooMachineError("Trying to start an already "
                                     "started vm %s" % label)

        vm_info = self.db.view_machine_by_label(label)

        if revert:
            virtualbox_args = [self.options.virtualbox.path, "snapshot", label]
            if vm_info.snapshot:
                log.debug("Using snapshot {0} for virtual machine "
                          "{1}".format(vm_info.snapshot, label))
                virtualbox_args.extend(["restore", vm_info.snapshot])
            else:
                log.debug("Using current snapshot for virtual machine "
                          "{0}".format(label))
                virtualbox_args.extend(["restorecurrent"])

            try:
                if subprocess.call(virtualbox_args,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE):
                    raise CuckooMachineError("VBoxManage exited with error "
                                             "restoring the machine's snapshot")
            except OSError as e:
                raise CuckooMachineError("VBoxManage failed restoring the "
                                         "machine: %s" % e)

            self._wait_status(label, self.SAVED)
        else:
            # It is quite possible that if a lot happens during the various
            # longterm runs that the harddisk starts to scatter. Therefore
            # optimize the harddisk right before every run.
            hdd_uuid = self._vminfo(label).get("IDE-ImageUUID-0-0")
            if hdd_uuid:
                try:
                    subprocess.check_call([self.options.virtualbox.path,
                                           "modifyhd", hdd_uuid, "--compact"])
                except subprocess.CalledProcessError as e:
                    log.warning("Error optimizing HDD of VM %s: %s", label, e)

        try:
            args = [
                self.options.virtualbox.path,
                "startvm", label,
                "--type", self.options.virtualbox.mode
            ]

            proc = subprocess.Popen(args,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            output, err = proc.communicate()
            if err:
                raise OSError(err)
        except OSError as e:
            raise CuckooMachineError("VBoxManage failed starting the machine "
                                     "in %s mode: %s" %
                                     (self.options.virtualbox.mode.upper(), e))
        self._wait_status(label, self.RUNNING)

        if vm_info.rdp_port:
            try:
                args = [
                    self.options.virtualbox.path, "controlvm",
                    label, "vrde", "on",
                ]
                subprocess.check_output(args)

                args = [
                    self.options.virtualbox.path, "controlvm",
                    label, "vrdeport", "%s" % vm_info.rdp_port,
                ]
                subprocess.check_output(args)
            except subprocess.CalledProcessError:
                log.exception("Error enabling VRDE support")

    def stop(self, label):
        """Stops a virtual machine.
        @param label: virtual machine name.
        @raise CuckooMachineError: if unable to stop.
        """
        log.debug("Stopping vm %s" % label)

        if self._status(label) in [self.POWEROFF, self.ABORTED]:
            raise CuckooMachineError("Trying to stop an already stopped "
                                     "vm %s" % label)

        try:
            proc = subprocess.Popen([self.options.virtualbox.path,
                                     "controlvm", label, "poweroff"],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            # Sometimes VBoxManage stucks when stopping vm so we needed
            # to add a timeout and kill it after that.
            stop_me = 0
            while proc.poll() is None:
                if stop_me < int(self.options_globals.timeouts.vm_state):
                    time.sleep(1)
                    stop_me += 1
                else:
                    log.debug("Stopping vm %s timeouted. Killing" % label)
                    proc.terminate()

            if proc.returncode != 0 and \
                    stop_me < int(self.options_globals.timeouts.vm_state):
                log.debug("VBoxManage exited with error "
                          "powering off the machine")
        except OSError as e:
            raise CuckooMachineError("VBoxManage failed powering off the "
                                     "machine: %s" % e)
        self._wait_status(label, [self.POWEROFF, self.ABORTED, self.SAVED])

    def _list(self):
        """Lists virtual machines installed.
        @return: virtual machine names list.
        """
        try:
            proc = subprocess.Popen([self.options.virtualbox.path,
                                     "list", "vms"],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            output, _ = proc.communicate()
        except OSError as e:
            raise CuckooMachineError("VBoxManage error listing "
                                     "installed machines: %s" % e)

        machines = []
        for line in output.split("\n"):
            try:
                label = line.split('"')[1]
                if label == "<inaccessible>":
                    log.warning("Found an inaccessible virtual machine, "
                                "please check its state.")
                else:
                    machines.append(label)
            except IndexError:
                continue

        return machines

    def _status(self, label):
        """Gets current status of a vm.
        @param label: virtual machine name.
        @return: status string.
        """
        log.debug("Getting status for %s" % label)

        # Fetch the VMState variable obtained through the showvminfo command
        # and if it fails, return error.
        status = self._vminfo(label).get("VMState", self.ERROR).lower()

        # Report back status.
        self.set_status(label, status)
        return status

    def dump_memory(self, label, path):
        """Takes a memory dump.
        @param path: path to where to store the memory dump.
        """
        try:
            subprocess.call([self.options.virtualbox.path, "debugvm",
                             label, "dumpguestcore", "--filename", path],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
            log.info("Successfully generated memory dump for virtual machine "
                     "with label %s to path %s", label, path)
        except OSError as e:
            raise CuckooMachineError("VBoxManage failed to take a memory "
                                     "dump of the machine with label %s: %s" %
                                     (label, e))
