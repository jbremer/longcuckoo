# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import ConfigParser

from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.exceptions import CuckooOperationalError
from lib.cuckoo.common.objects import Dictionary

class ConfigSection(object):
    def __init__(self, file_name, section, items):
        self.file_name = file_name
        self.section = section
        self.items = items

    def __getattr__(self, key):
        attr = "%s.%s.%s" % (self.file_name, self.section, key)

        # We make one exception here, namely, for the database connection.
        if self.file_name == "cuckoo" and self.section == "database":
            return self.items[key]

        # Recursive dependencies and all that.
        from lib.cuckoo.core.database import Database
        return Database().config_get(attr)

    __getitem__ = __getattr__

    def get(self, key, default=None):
        value = self.__getitem__(key)
        if value is None:
            value = default
        return value

    def __contains__(self, key):
        return self.get(key) is not None

class Config(object):
    """Configuration file parser."""

    def __init__(self, file_name="cuckoo", cfg=None):
        """
        @param file_name: file name without extension.
        @param cfg: configuration file path.
        """
        config = ConfigParser.ConfigParser()

        if cfg:
            config.read(cfg)
        else:
            config.read(os.path.join(CUCKOO_ROOT, "conf", "%s.conf" % file_name))

        self.sections = {}

        for section in config.sections():
            self.sections[section] = Dictionary()
            for name, raw_value in config.items(section):
                try:
                    # Ugly fix to avoid '0' and '1' to be parsed as a
                    # boolean value.
                    # We raise an exception to goto fail^w parse it
                    # as integer.
                    if config.get(section, name) in ["0", "1"]:
                        raise ValueError

                    value = config.getboolean(section, name)
                except ValueError:
                    try:
                        value = config.getint(section, name)
                    except ValueError:
                        value = config.get(section, name)

                self.sections[section][name] = value

            cs = ConfigSection(file_name, section, self.sections[section])
            setattr(self, section, cs)

    def get(self, section):
        """Get option.
        @param section: section to fetch.
        @raise CuckooOperationalError: if section not found.
        @return: option value.
        """
        try:
            return getattr(self, section)
        except AttributeError as e:
            raise CuckooOperationalError("Option %s is not found in "
                                         "configuration, error: %s" %
                                         (section, e))
