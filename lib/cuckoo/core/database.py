# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import json
import logging
from datetime import datetime, timedelta

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.exceptions import CuckooDatabaseError
from lib.cuckoo.common.exceptions import CuckooOperationalError
from lib.cuckoo.common.exceptions import CuckooDependencyError
from lib.cuckoo.common.objects import File, URL
from lib.cuckoo.common.utils import create_folder, Singleton, time_duration

try:
    from sqlalchemy import create_engine, Column, or_
    from sqlalchemy import Integer, String, Boolean, DateTime, Enum
    from sqlalchemy import ForeignKey, Text, Index, Table
    from sqlalchemy.ext.declarative import declarative_base
    from sqlalchemy.exc import SQLAlchemyError, IntegrityError
    from sqlalchemy.orm import sessionmaker, relationship, joinedload, backref, aliased
    from sqlalchemy.orm.session import make_transient
    from sqlalchemy.pool import NullPool
    Base = declarative_base()
except ImportError:
    raise CuckooDependencyError("Unable to import sqlalchemy "
                                "(install with `pip install sqlalchemy`)")

log = logging.getLogger(__name__)

null = None

SCHEMA_VERSION = "5adbab2b7915"
TASK_PENDING = "pending"
TASK_RUNNING = "running"
TASK_COMPLETED = "completed"
TASK_RECOVERED = "recovered"
TASK_REPORTED = "reported"
TASK_SCHEDULED = "scheduled"
TASK_UNSCHEDULED = "unscheduled"
TASK_FAILED_ANALYSIS = "failed_analysis"
TASK_FAILED_PROCESSING = "failed_processing"

# Task type (single or recurrent)
TASK_SINGLE = "single"
TASK_RECURRENT = "recurrent"

# Secondary table used in association Machine - Tag.
machines_tags = Table(
    "machines_tags", Base.metadata,
    Column("machine_id", Integer, ForeignKey("machines.id")),
    Column("tag_id", Integer, ForeignKey("tags.id"))
)

# Secondary table used in association Task - Tag.
tasks_tags = Table(
    "tasks_tags", Base.metadata,
    Column("task_id", Integer, ForeignKey("tasks.id")),
    Column("tag_id", Integer, ForeignKey("tags.id"))
)

class Configuration(Base):
    """Cuckoo configuration values."""
    __tablename__ = "config"

    id = Column(Integer(), primary_key=True)
    key = Column(Text(), nullable=False)
    type_ = Column(Text(), nullable=True)
    value = Column(Text(), nullable=True)

class Machine(Base):
    """Configured virtual machines to be used as guests."""
    __tablename__ = "machines"

    id = Column(Integer(), primary_key=True)
    name = Column(String(255), nullable=False)
    label = Column(String(255), nullable=False)
    ip = Column(String(255), nullable=False)
    platform = Column(String(255), nullable=False)
    tags = relationship("Tag", secondary=machines_tags, single_parent=True,
                        backref=backref("machine"))
    interface = Column(String(255), nullable=True)
    snapshot = Column(String(255), nullable=True)
    locked_by = Column(Integer(), nullable=True, default=None)
    status = Column(String(255), nullable=True)
    resultserver_ip = Column(String(255), nullable=False)
    resultserver_port = Column(String(255), nullable=False)
    rdp_port = Column(String(16), nullable=True)

    def __repr__(self):
        return "<Machine('{0}','{1}')>".format(self.id, self.name)

    def to_dict(self):
        """Converts object to dict.
        @return: dict
        """
        d = {}
        for column in self.__table__.columns:
            value = getattr(self, column.name)
            if isinstance(value, datetime):
                d[column.name] = value.strftime("%Y-%m-%d %H:%M:%S")
            else:
                d[column.name] = value

        # Tags are a relation so no column to iterate.
        d["tags"] = [tag.name for tag in self.tags]
        return d

    def to_json(self):
        """Converts object to JSON.
        @return: JSON data
        """
        return json.dumps(self.to_dict())

    def __init__(self, name, label, ip, platform, interface, snapshot,
                 resultserver_ip, resultserver_port, rdp_port, locked_by):
        self.name = name
        self.label = label
        self.ip = ip
        self.platform = platform
        self.interface = interface
        self.snapshot = snapshot
        self.resultserver_ip = resultserver_ip
        self.resultserver_port = resultserver_port
        self.rdp_port = rdp_port
        self.locked_by = locked_by

class Tag(Base):
    """Tag describing anything you want."""
    __tablename__ = "tags"

    id = Column(Integer(), primary_key=True)
    name = Column(String(255), nullable=False, unique=True)

    def __repr__(self):
        return "<Tag('{0}','{1}')>".format(self.id, self.name)

    def __init__(self, name):
        self.name = name

class Guest(Base):
    """Tracks guest run."""
    __tablename__ = "guests"

    id = Column(Integer(), primary_key=True)
    name = Column(String(255), nullable=False)
    label = Column(String(255), nullable=False)
    manager = Column(String(255), nullable=False)
    started_on = Column(DateTime(timezone=False),
                        default=datetime.now,
                        nullable=False)
    shutdown_on = Column(DateTime(timezone=False), nullable=True)
    task_id = Column(Integer,
                     ForeignKey("tasks.id"),
                     nullable=False,
                     unique=True)

    def __repr__(self):
        return "<Guest('{0}','{1}')>".format(self.id, self.name)

    def to_dict(self):
        """Converts object to dict.
        @return: dict
        """
        d = {}
        for column in self.__table__.columns:
            value = getattr(self, column.name)
            if isinstance(value, datetime):
                d[column.name] = value.strftime("%Y-%m-%d %H:%M:%S")
            else:
                d[column.name] = value
        return d

    def to_json(self):
        """Converts object to JSON.
        @return: JSON data
        """
        return json.dumps(self.to_dict())

    def __init__(self, name, label, manager):
        self.name = name
        self.label = label
        self.manager = manager

class Sample(Base):
    """Submitted files details."""
    __tablename__ = "samples"

    id = Column(Integer(), primary_key=True)
    file_size = Column(Integer(), nullable=False)
    file_type = Column(Text(), nullable=False)
    md5 = Column(String(32), nullable=False)
    crc32 = Column(String(8), nullable=False)
    sha1 = Column(String(40), nullable=False)
    sha256 = Column(String(64), nullable=False)
    sha512 = Column(String(128), nullable=False)
    ssdeep = Column(String(255), nullable=True)
    __table_args__ = Index("hash_index", "md5", "crc32", "sha1",
                           "sha256", "sha512", unique=True),

    def __repr__(self):
        return "<Sample('{0}','{1}')>".format(self.id, self.sha256)

    def to_dict(self):
        """Converts object to dict.
        @return: dict
        """
        d = {}
        for column in self.__table__.columns:
            d[column.name] = getattr(self, column.name)
        return d

    def to_json(self):
        """Converts object to JSON.
        @return: JSON data
        """
        return json.dumps(self.to_dict())

    def __init__(self, md5, crc32, sha1, sha256, sha512,
                 file_size, file_type=None, ssdeep=None):
        self.md5 = md5
        self.sha1 = sha1
        self.crc32 = crc32
        self.sha256 = sha256
        self.sha512 = sha512
        self.file_size = file_size
        if file_type:
            self.file_type = file_type
        if ssdeep:
            self.ssdeep = ssdeep

class Error(Base):
    """Analysis errors."""
    __tablename__ = "errors"

    id = Column(Integer(), primary_key=True)
    message = Column(String(255), nullable=False)
    task_id = Column(Integer, ForeignKey("tasks.id"), nullable=False)

    def to_dict(self):
        """Converts object to dict.
        @return: dict
        """
        d = {}
        for column in self.__table__.columns:
            d[column.name] = getattr(self, column.name)
        return d

    def to_json(self):
        """Converts object to JSON.
        @return: JSON data
        """
        return json.dumps(self.to_dict())

    def __init__(self, message, task_id):
        self.message = message
        self.task_id = task_id

    def __repr__(self):
        return "<Error('{0}','{1}','{2}')>".format(self.id, self.message, self.task_id)

class Experiment(Base):
    """Experiment regroups a list of tasks together."""
    __tablename__ = "experiments"

    id = Column(Integer(), primary_key=True)
    name = Column(Text(), nullable=True, unique=True)
    added_on = Column(DateTime(timezone=False),
                      default=datetime.now,
                      nullable=False)
    delta = Column(String(), nullable=True)
    # Amount of runs left for this Experiment.
    runs = Column(Integer(), nullable=True)
    # Amount of times this Experiment has ran already.
    times = Column(Integer(), nullable=True)
    machine_name = Column(Text(), nullable=True)

class Task(Base):
    """Analysis task queue."""
    __tablename__ = "tasks"

    id = Column(Integer(), primary_key=True)
    repeat = Column(Enum(TASK_SINGLE, TASK_RECURRENT, name="repeat_type"), server_default=TASK_SINGLE, nullable=False)
    target = Column(Text(), nullable=False)
    category = Column(String(255), nullable=False)
    timeout = Column(Integer(), server_default="0", nullable=False)
    priority = Column(Integer(), server_default="1", nullable=False)
    custom = Column(String(255), nullable=True)
    machine = Column(String(255), nullable=True)
    package = Column(String(255), nullable=True)
    tags = relationship("Tag", secondary=tasks_tags, single_parent=True,
                        backref=backref("task"), lazy="subquery")
    options = Column(String(255), nullable=True)
    platform = Column(String(255), nullable=True)
    memory = Column(Boolean, nullable=False, default=False)
    enforce_timeout = Column(Boolean, nullable=False, default=False)
    clock = Column(DateTime(timezone=False),
                   default=datetime.now,
                   nullable=False)
    added_on = Column(DateTime(timezone=False),
                      default=datetime.now,
                      nullable=False)
    started_on = Column(DateTime(timezone=False), nullable=True)
    completed_on = Column(DateTime(timezone=False), nullable=True)
    status = Column(Enum(TASK_PENDING, TASK_RUNNING, TASK_COMPLETED,
                         TASK_REPORTED, TASK_RECOVERED, TASK_SCHEDULED,
                         TASK_UNSCHEDULED, TASK_FAILED_ANALYSIS,
                         TASK_FAILED_PROCESSING, name="status_type"),
                    server_default=TASK_PENDING,
                    nullable=False)
    sample_id = Column(Integer, ForeignKey("samples.id"), nullable=True)
    experiment_id = Column(Integer, ForeignKey("experiments.id"), nullable=False)

    sample = relationship("Sample", backref="tasks")
    experiment = relationship("Experiment", backref=backref("tasks", lazy="dynamic"), lazy="joined")

    guest = relationship("Guest", uselist=False, backref="tasks", cascade="save-update, delete")
    errors = relationship("Error", backref="tasks", cascade="save-update, delete")

    def to_dict(self):
        """Converts object to dict.
        @return: dict
        """
        d = {}
        for column in self.__table__.columns:
            value = getattr(self, column.name)
            if isinstance(value, datetime):
                d[column.name] = value.strftime("%Y-%m-%d %H:%M:%S")
            else:
                d[column.name] = value

        # Tags are a relation so no column to iterate.
        d["tags"] = [tag.name for tag in self.tags]
        return d

    def to_json(self):
        """Converts object to JSON.
        @return: JSON data
        """
        return json.dumps(self.to_dict())

    def __init__(self, target=None):
        self.target = target

    def __repr__(self):
        return "<Task('{0}','{1}')>".format(self.id, self.target)

class AlembicVersion(Base):
    """Table used to pinpoint actual database schema release."""
    __tablename__ = "alembic_version"

    version_num = Column(String(32), nullable=False, primary_key=True)

class Database(object):
    """Analysis queue database.

    This class handles the creation of the database user for internal queue
    management. It also provides some functions for interacting with it.
    """
    __metaclass__ = Singleton

    def __init__(self, dsn=None, schema_check=True):
        """@param dsn: database connection string.
        @param schema_check: disable or enable the db schema version check
        """
        self.cfg = Config()

        if dsn:
            self._connect_database(dsn)
        elif self.cfg.database.connection:
            self._connect_database(self.cfg.database.connection)
        else:
            db_file = os.path.join(CUCKOO_ROOT, "db", "cuckoo.db")
            if not os.path.exists(db_file):
                db_dir = os.path.dirname(db_file)
                if not os.path.exists(db_dir):
                    try:
                        create_folder(folder=db_dir)
                    except CuckooOperationalError as e:
                        raise CuckooDatabaseError("Unable to create database directory: {0}".format(e))

            self._connect_database("sqlite:///%s" % db_file)

        # Disable SQL logging. Turn it on for debugging.
        self.engine.echo = False
        # Connection timeout.
        if self.cfg.database.timeout:
            self.engine.pool_timeout = self.cfg.database.timeout
        else:
            self.engine.pool_timeout = 60
        # Create schema.
        try:
            Base.metadata.create_all(self.engine)
        except SQLAlchemyError as e:
            raise CuckooDatabaseError("Unable to create or connect to database: {0}".format(e))

        # Get db session.
        self.Session = sessionmaker(bind=self.engine)

        # Deal with schema versioning.
        # TODO: it's a little bit dirty, needs refactoring.
        tmp_session = self.Session()
        if not tmp_session.query(AlembicVersion).count():
            # Set database schema version.
            tmp_session.add(AlembicVersion(version_num=SCHEMA_VERSION))
            try:
                tmp_session.commit()
            except SQLAlchemyError as e:
                raise CuckooDatabaseError("Unable to set schema version: {0}".format(e))
                tmp_session.rollback()
            finally:
                tmp_session.close()
        else:
            # Check if db version is the expected one.
            last = tmp_session.query(AlembicVersion).first()
            tmp_session.close()
            if last.version_num != SCHEMA_VERSION and schema_check:
                raise CuckooDatabaseError("DB schema version mismatch: found "
                                          "{0}, expected {1}. Try to apply all "
                                          "migrations.".format(last.version_num,
                                          SCHEMA_VERSION))

    def __del__(self):
        """Disconnects pool."""
        self.engine.dispose()

    def _connect_database(self, connection_string):
        """Connect to a Database.
        @param connection_string: Connection string specifying the database
        """
        try:
            self.engine = create_engine(connection_string, poolclass=NullPool)
        except ImportError as e:
            lib = e.message.split()[-1]
            raise CuckooDependencyError("Missing database driver, unable to "
                                        "import %s (install with `pip "
                                        "install %s`)" % (lib, lib))

    def _get_or_create(self, session, model, **kwargs):
        """Get an ORM instance or create it if not exist.
        @param session: SQLAlchemy session object
        @param model: model to query
        @return: row instance
        """
        instance = session.query(model).filter_by(**kwargs).first()
        return instance or model(**kwargs)

    def _config_unserialize(self, type_, value):
        """Convert the value to its original type.
        @param type_: type
        @param value: value
        """
        bool_true = {
            "true": True,
            "1": True,
        }

        types = {
            "bool": lambda value: bool_true.get(value, False),
            "int": int,
            "str": str,
        }
        if type_ not in types:
            log.warning("Invalid configuration type: %s", type_)
            return value

        return types[type_](value)

    def config_get(self, key):
        """Get the value of a configuration entry.
        @param key: key of the configuration entry
        @return: value of the configuration entry
        """
        session = self.Session()
        try:
            row = session.query(Configuration).filter_by(key=key).first()
        except SQLAlchemyError as e:
            log.debug("Configuration value not set (%s): {0}".format(key, e))
            return None
        finally:
            session.close()

        if row:
            return self._config_unserialize(row.type_, row.value)

        return None

    def config_all(self):
        """Return all configuration entries from the database."""
        session = self.Session()
        try:
            entries = session.query(Configuration).all()
        except SQLAlchemyError as e:
            log.debug("No configuration entries found: {0}".format(e))
            return []
        finally:
            session.close()

        ret = {}
        for row in entries:
            ret[row.key] = self._config_unserialize(row.type_, row.value)

        return ret

    def config_set(self, key, value):
        """Set the value of a configuration entry.
        @param key: key of the configuration entry
        @param value: value of the configuration entry
        """
        session = self.Session()
        try:
            entry = self._get_or_create(session, Configuration, key=key)
            entry.type_ = value.__class__.__name__
            entry.value = value
            session.add(entry)
            session.commit()
        except SQLAlchemyError as e:
            log.debug("Configuration value not set (%s): {0}".format(key, e))
            session.rollback()
            return None
        finally:
            session.close()
        return value

    def clean_machines(self):
        """Clean old stored machines and related tables."""
        # Secondary table.
        # TODO: this is better done via cascade delete.
        self.engine.execute(machines_tags.delete())

        session = self.Session()
        try:
            session.query(Machine).delete()
            session.commit()
        except SQLAlchemyError as e:
            log.debug("Database error cleaning machines: {0}".format(e))
            session.rollback()
        finally:
            session.close()

    def add_machine(self, name, label, ip, platform, tags, interface,
                    snapshot, resultserver_ip, resultserver_port, rdp_port,
                    locked_by):
        """Add a guest machine.
        @param name: machine id
        @param label: machine label
        @param ip: machine IP address
        @param platform: machine supported platform
        @param interface: sniffing interface for this machine
        @param snapshot: snapshot name to use instead of the current one, if configured
        @param resultserver_ip: IP address of the Result Server
        @param resultserver_port: port of the Result Server
        @param locked_by: locked by experiment id
        """
        session = self.Session()
        machine = Machine(name=name,
                          label=label,
                          ip=ip,
                          platform=platform,
                          interface=interface,
                          snapshot=snapshot,
                          resultserver_ip=resultserver_ip,
                          resultserver_port=resultserver_port,
                          rdp_port=rdp_port,
                          locked_by=locked_by)
        # Deal with tags format (i.e., foo,bar,baz)
        if tags:
            for tag in tags.split(","):
                if not tag.strip():
                    continue

                tag = self._get_or_create(session, Tag, name=tag.strip())
                machine.tags.append(tag)

        try:
            session.add(machine)
            session.commit()
            session.refresh(machine)
        except SQLAlchemyError as e:
            log.debug("Database error adding machine: {0}".format(e))
            session.rollback()
            return None
        finally:
            session.close()

        return machine

    def set_status(self, task_id, status):
        """Set task status.
        @param task_id: task identifier
        @param status: status string
        @return: operation status
        """
        session = self.Session()
        try:
            row = session.query(Task).get(task_id)
            row.status = status

            if status == TASK_RUNNING:
                row.started_on = datetime.now()
            elif status == TASK_COMPLETED:
                row.completed_on = datetime.now()

            session.commit()
        except SQLAlchemyError as e:
            log.debug("Database error setting status: {0}".format(e))
            session.rollback()
        finally:
            session.close()

    def fetch(self, lock=True, status=TASK_PENDING):
        """Fetches a task waiting to be processed and locks it for running.
        @return: None or task
        """
        session = self.Session()
        row = None

        try:
            task1, task2 = aliased(Task), aliased(Task)

            q = session.query(task1.experiment_id)
            q = q.filter(task1.id != task2.id)
            q = q.filter(task1.experiment_id == task2.experiment_id)
            q = q.filter(task2.status == TASK_RUNNING)

            row = session.query(Task)
            row = row.filter(Task.status == status)
            row = row.filter(Task.added_on <= datetime.now())
            row = row.filter(~Task.experiment_id.in_(q))
            row = row.order_by(Task.priority.desc(), Task.added_on).first()
            if not row:
                return None

            if lock:
                self.set_status(task_id=row.id, status=TASK_RUNNING)
                session.refresh(row)
        except SQLAlchemyError as e:
            log.debug("Database error fetching task: {0}".format(e))
            session.rollback()
        finally:
            session.close()

        return row

    def guest_start(self, task_id, name, label, manager):
        """Logs guest start.
        @param task_id: task identifier
        @param name: vm name
        @param label: vm label
        @param manager: vm manager
        @return: guest row id
        """
        session = self.Session()
        guest = Guest(name, label, manager)
        try:
            session.query(Task).get(task_id).guest = guest
            session.commit()
            session.refresh(guest)
        except SQLAlchemyError as e:
            log.debug("Database error logging guest start: {0}".format(e))
            session.rollback()
            return None
        finally:
            session.close()
        return guest.id

    def guest_remove(self, guest_id):
        """Removes a guest start entry."""
        session = self.Session()
        try:
            guest = session.query(Guest).get(guest_id)
            session.delete(guest)
            session.commit()
        except SQLAlchemyError as e:
            log.debug("Database error logging guest remove: {0}".format(e))
            session.rollback()
            return None
        finally:
            session.close()

    def guest_stop(self, guest_id):
        """Logs guest stop.
        @param guest_id: guest log entry id
        """
        session = self.Session()
        try:
            session.query(Guest).get(guest_id).shutdown_on = datetime.now()
            session.commit()
        except SQLAlchemyError as e:
            log.debug("Database error logging guest stop: {0}".format(e))
            session.rollback()
        except TypeError:
            log.warning("Data inconsistency in guests table detected, it might be a crash leftover. Continue")
            session.rollback()
        finally:
            session.close()

    def list_machines(self, locked=None, status=None):
        """Lists virtual machines.
        @return: list of virtual machines
        """
        session = self.Session()
        try:
            machines = session.query(Machine).options(joinedload("tags"))

            # When used, machines are locked by an analysis task. For normal
            # tasks the machine is only locked to one analysis, however, for
            # longterm analysis experiments, machines are locked to one
            # experiment for as long as the experiment is operational.
            if locked is True:
                machines = machines.filter(Machine.locked_by != null)
            elif locked is False:
                machines = machines.filter(Machine.locked_by == null)
            elif locked is not None:
                log.error("Invalid 'locked' value: %r", locked)

            # List by machine status.
            if status is not None:
                machines = machines.filter_by(status=status)

            machines = machines.order_by(Machine.id).all()
        except SQLAlchemyError as e:
            log.debug("Database error listing machines: {0}".format(e))
            return []
        finally:
            session.close()
        return machines

    def lock_machine(self, name=None, platform=None, tags=None, locked_by=None):
        """Places a lock on a free virtual machine.
        @param name: optional virtual machine name
        @param platform: optional virtual machine platform
        @param tags: optional tags required (list)
        @return: locked machine
        """
        session = self.Session()

        # Preventive checks.
        if name and platform:
            # Wrong usage.
            log.error("You can select machine only by name or by platform.")
            return None
        elif name and tags:
            # Also wrong usage.
            log.error("You can select machine only by name or by tags.")
            return None

        try:
            machines = session.query(Machine).order_by(Machine.id)
            if name:
                machines = machines.filter_by(name=name)
            if platform:
                machines = machines.filter_by(platform=platform)
            if tags:
                for tag in tags:
                    machines = machines.filter(Machine.tags.any(name=tag.name))

            # Check if there are any machines that satisfy the
            # selection requirements.
            if not machines.count():
                raise CuckooOperationalError("No machines match selection criteria.")

            # Get the machine already reserved by the experiment.
            machine = machines.filter_by(locked_by=locked_by).first()
            if not machine:
                # Get a free machine.
                machine = machines.filter_by(locked_by=None).first()
        except SQLAlchemyError as e:
            log.debug("Database error locking machine: {0}".format(e))
            session.close()
            return None

        if machine:
            # This machine is now locked by the specified experiment.
            machine.locked_by = locked_by

            # Update the experiment to reflect the machine name.
            experiment = session.query(Experiment).get(locked_by)
            if experiment is not None:
                experiment.machine_name = machine.name

            try:
                session.commit()
                session.refresh(machine)
            except SQLAlchemyError as e:
                log.debug("Database error locking machine: {0}".format(e))
                session.rollback()
                return None
            finally:
                session.close()

        return machine

    def unlock_machine(self, label):
        """Remove lock form a virtual machine.
        @param label: virtual machine label
        @return: unlocked machine
        """
        session = self.Session()
        try:
            machine = session.query(Machine).filter_by(label=label).first()
        except SQLAlchemyError as e:
            log.debug("Database error unlocking machine: {0}".format(e))
            session.close()
            return None

        if machine:
            machine.locked_by = None
            try:
                session.commit()
                session.refresh(machine)
            except SQLAlchemyError as e:
                log.debug("Database error locking machine: {0}".format(e))
                session.rollback()
                return None
            finally:
                session.close()

        return machine

    def unlock_machine_by_experiment(self, experiment):
        """Remove lock from a virtual machine.
        @param experiment: experiment id
        @return: unlocked machine
        """
        session = self.Session()
        try:
            machine = session.query(Machine).filter(Machine.locked_by == experiment).first()
        except SQLAlchemyError as e:
            log.debug("Database error unlocking machine: {0}".format(e))
            session.close()
            return None

        if machine:
            machine.locked_by = None
            try:
                session.commit()
                session.refresh(machine)
            except SQLAlchemyError as e:
                log.debug("Database error locking machine: {0}".format(e))
                session.rollback()
                return None
            finally:
                session.close()

        return machine

    def count_machines_available(self, locked_by=None):
        """How many virtual machines are ready for analysis.
        @return: free virtual machines count
        """
        session = self.Session()
        try:
            machines_count = session.query(Machine).filter(or_(Machine.locked_by == locked_by, Machine.locked_by == null)).count()
        except SQLAlchemyError as e:
            log.debug("Database error counting machines: {0}".format(e))
            return 0
        finally:
            session.close()
        return machines_count

    def set_machine_status(self, label, status):
        """Set status for a virtual machine.
        @param label: virtual machine label
        @param status: new virtual machine status
        """
        session = self.Session()
        try:
            machine = session.query(Machine).filter_by(label=label).first()
        except SQLAlchemyError as e:
            log.debug("Database error setting machine status: {0}".format(e))
            session.close()
            return

        if machine:
            machine.status = status
            try:
                session.commit()
                session.refresh(machine)
            except SQLAlchemyError as e:
                log.debug("Database error setting machine status: {0}".format(e))
                session.rollback()
            finally:
                session.close()
        else:
            session.close()

    def add_error(self, message, task_id):
        """Add an error related to a task.
        @param message: error message
        @param task_id: ID of the related task
        """
        session = self.Session()
        error = Error(message=message, task_id=task_id)
        session.add(error)
        try:
            session.commit()
        except SQLAlchemyError as e:
            log.debug("Database error adding error log: {0}".format(e))
            session.rollback()
        finally:
            session.close()

    # The following functions are mostly used by external utils.

    def add(self, obj, timeout=0, package="", options="", priority=1,
            custom="", machine="", platform="", tags=None,
            memory=False, enforce_timeout=False, clock=None,
            name=None, repeat=None, added_on=None, status=TASK_PENDING,
            delta=None, runs=None):
        """Add a task to database.
        @param obj: object to add (File or URL).
        @param timeout: selected timeout.
        @param options: analysis options.
        @param priority: analysis priority.
        @param custom: custom options.
        @param machine: selected machine.
        @param platform: platform.
        @param tags: optional tags that must be set for machine selection
        @param memory: toggle full memory dump.
        @param enforce_timeout: toggle full timeout execution.
        @param clock: virtual machine clock time
        @param repeat: single or recurring analysis
        @return: cursor or None.
        """
        session = self.Session()

        # Convert empty strings and None values to a valid int
        if not timeout:
            timeout = 0
        if not priority:
            priority = 1

        if timeout <= 0:
            timeout = self.cfg.timeouts.default

        if isinstance(obj, File):
            sample = Sample(md5=obj.get_md5(),
                            crc32=obj.get_crc32(),
                            sha1=obj.get_sha1(),
                            sha256=obj.get_sha256(),
                            sha512=obj.get_sha512(),
                            file_size=obj.get_size(),
                            file_type=obj.get_type(),
                            ssdeep=obj.get_ssdeep())
            session.add(sample)

            try:
                session.commit()
            except IntegrityError:
                session.rollback()
                try:
                    sample = session.query(Sample).filter_by(md5=obj.get_md5()).first()
                except SQLAlchemyError as e:
                    log.debug("Error querying sample for hash: {0}".format(e))
                    session.close()
                    return None
            except SQLAlchemyError as e:
                log.debug("Database error adding task: {0}".format(e))
                session.close()
                return None

            task = Task(obj.file_path)
            task.sample_id = sample.id
        elif isinstance(obj, URL):
            task = Task(obj.url)

        # Create an experiment
        experiment = Experiment(name=name, delta=delta, runs=runs, times=0)
        session.add(experiment)
        try:
            session.commit()
            session.refresh(experiment)
        except SQLAlchemyError as e:
            log.debug("Database error adding experiment: {0}".format(e))
            session.close()
            return None

        task.category = obj.__class__.__name__.lower()
        task.timeout = min(timeout, self.cfg.timeouts.critical)
        task.package = package
        task.options = options
        task.priority = priority
        task.custom = custom
        task.machine = machine
        task.platform = platform
        task.memory = memory
        task.enforce_timeout = enforce_timeout
        task.experiment_id = experiment.id
        task.repeat = repeat
        task.added_on = added_on
        task.status = status

        # Deal with tags format (i.e., foo,bar,baz)
        if tags:
            for tag in tags.split(","):
                if not tag.strip():
                    continue

                tag = self._get_or_create(session, Tag, name=tag.strip())
                task.tags.append(tag)

        if clock:
            if isinstance(clock, basestring):
                try:
                    task.clock = datetime.strptime(clock, "%m-%d-%Y %H:%M:%S")
                except ValueError:
                    log.warning("The date you specified has an invalid format, using current timestamp.")
                    task.clock = datetime.now()
            else:
                task.clock = clock

        try:
            session.add(task)
            session.commit()
            session.refresh(task)
            task_id = task.id
        except SQLAlchemyError as e:
            log.debug("Database error adding task: {0}".format(e))
            session.rollback()
            return None
        finally:
            session.close()

        return task_id

    def add_path(self, file_path, timeout=0, package="", options="",
                 priority=1, custom="", machine="", platform="", tags=None,
                 memory=False, enforce_timeout=False, clock=None,
                 experiment=None, repeat=None, added_on=None,
                 status=TASK_PENDING, name=None, delta=None, runs=None):
        """Add a task to database from file path.
        @param file_path: sample path.
        @param timeout: selected timeout.
        @param options: analysis options.
        @param priority: analysis priority.
        @param custom: custom options.
        @param machine: selected machine.
        @param platform: platform.
        @param tags: Tags required in machine selection
        @param memory: toggle full memory dump.
        @param enforce_timeout: toggle full timeout execution.
        @param clock: virtual machine clock time
        @return: cursor or None.
        """
        if not file_path or not os.path.exists(file_path):
            log.warning("File does not exist: %s.", file_path)
            return None

        # Convert empty strings and None values to a valid int
        if not timeout:
            timeout = 0
        if not priority:
            priority = 1

        return self.add(File(file_path), timeout, package, options, priority,
                        custom, machine, platform, tags, memory,
                        enforce_timeout, clock, name, repeat, added_on, status,
                        delta, runs)

    def add_url(self, url, timeout=0, package="", options="", priority=1,
                custom="", machine="", platform="", tags=None, memory=False,
                enforce_timeout=False, clock=None, name=None, repeat=None,
                added_on=None, status=TASK_PENDING, delta=None, runs=None):
        """Add a task to database from url.
        @param url: url.
        @param timeout: selected timeout.
        @param options: analysis options.
        @param priority: analysis priority.
        @param custom: custom options.
        @param machine: selected machine.
        @param platform: platform.
        @param tags: tags for machine selection
        @param memory: toggle full memory dump.
        @param enforce_timeout: toggle full timeout execution.
        @param clock: virtual machine clock time
        @return: cursor or None.
        """

        # Convert empty strings and None values to a valid int
        if not timeout:
            timeout = 0
        if not priority:
            priority = 1

        return self.add(URL(url), timeout, package, options, priority,
                        custom, machine, platform, tags, memory,
                        enforce_timeout, clock, name, repeat, added_on,
                        status, delta, runs)

    def start_task(self, task_id):
        session = self.Session()
        task = session.query(Task).get(task_id)

        if task.status in (TASK_SCHEDULED, TASK_UNSCHEDULED):
            task.added_on = datetime.now()
            session.commit()

        session.close()

    def reschedule(self, task_id):
        """Reschedule a task.
        @param task_id: ID of the task to reschedule.
        @return: ID of the newly created task.
        """
        task = self.view_task(task_id)
        if not task:
            return None

        if task.category == "file":
            add = self.add_path
        elif task.category == "url":
            add = self.add_url

        # Change status to recovered.
        session = self.Session()
        session.query(Task).get(task_id).status = TASK_RECOVERED
        try:
            session.commit()
        except SQLAlchemyError as e:
            log.debug("Database error rescheduling task: {0}".format(e))
            session.rollback()
            return False
        finally:
            session.close()

        # Normalize tags.
        if task.tags:
            tags = ",".join(tag.name for tag in task.tags)
        else:
            tags = task.tags

        return add(task.target, task.timeout, task.package, task.options,
                   task.priority, task.custom, task.machine, task.platform,
                   tags, task.memory, task.enforce_timeout, task.clock)

    def schedule(self, task_id, delta=None, timeout=None):
        session = self.Session()

        task = self.view_task(task_id)
        if not task:
            return None

        try:
            make_transient(task)
            task.id = None
            task.status = TASK_SCHEDULED
            task.started_on = None
            task.completed_on = None

            # If specified use the delta that has been provided, otherwise
            # fall back on the delta set for this experiment.
            if delta is None:
                delta = time_duration(task.experiment.delta)

            # Decrease the runcount and increase the times it was run.
            task.experiment.runs -= 1
            task.experiment.times += 1

            # If the runcount is one, release the machine lock after this
            # analysis by updating its repeat status to TASK_SINGLE.
            if task.experiment.runs == 1:
                task.repeat = TASK_SINGLE

            # Schedule the next task.
            task.added_on = task.added_on + timedelta(seconds=delta)

            if timeout is not None:
                task.timeout = timeout

            session.add(task)
            session.commit()
            session.refresh(task)
        except SQLAlchemyError as e:
            log.debug("Database error rescheduling task: {0}".format(e))
            session.rollback()
            return None
        finally:
            session.close()

        return task

    def list_experiments(self, limit=None, details=False, category=None,
                         offset=None, status=None, not_status=None):
        session = self.Session()
        try:
            experiments = session.query(Experiment).options(joinedload("tasks")).order_by(Experiment.id).all()
            for experiment in experiments:
                experiment.last_task = experiment.tasks.order_by(Task.id.desc()).first()
        except SQLAlchemyError as e:
            log.debug("Database error listing experiments: {0}".format(e))
            return []
        finally:
            session.close()
        return experiments

    def list_tasks(self, limit=None, details=False, category=None,
                   offset=None, status=None, sample_id=None, not_status=None,
                   experiment=None, completed_after=None, order_by=None):
        """Retrieve list of task.
        @param limit: specify a limit of entries.
        @param details: if details about must be included
        @param category: filter by category
        @param offset: list offset
        @param status: filter by task status
        @param experiment: experiment id
        @param sample_id: filter tasks for a sample
        @param not_status: exclude this task status from filter
        @param completed_after: only list tasks completed after this timestamp
        @param order_by: definition which field to sort by
        @return: list of tasks.
        """
        session = self.Session()
        try:
            search = session.query(Task)

            if status:
                if isinstance(status, (tuple, list)):
                    search = search.filter(Task.status.in_(status))
                else:
                    search = search.filter_by(status=status)
            if not_status:
                search = search.filter(~Task.status.in_(not_status))
            if category:
                search = search.filter_by(category=category)
            if details:
                search = search.options(joinedload("guest"), joinedload("errors"), joinedload("tags"))
            if experiment:
                search = search.filter_by(experiment_id=experiment)
            if sample_id is not None:
                search = search.filter_by(sample_id=sample_id)
            if completed_after:
                search = search.filter(Task.completed_on > completed_after)

            tasks = search.order_by(Task.added_on.desc())
            tasks = tasks.limit(limit).offset(offset).all()
        except SQLAlchemyError as e:
            log.debug("Database error listing tasks: {0}".format(e))
            return []
        finally:
            session.close()
        return tasks

    def count_tasks(self, status=None):
        """Count tasks in the database
        @param status: apply a filter according to the task status
        @return: number of tasks found
        """
        session = self.Session()
        try:
            if status:
                tasks_count = session.query(Task).filter_by(status=status).count()
            else:
                tasks_count = session.query(Task).count()
        except SQLAlchemyError as e:
            log.debug("Database error counting tasks: {0}".format(e))
            return 0
        finally:
            session.close()
        return tasks_count

    def view_task(self, task_id, details=False):
        """Retrieve information on a task.
        @param task_id: ID of the task to query.
        @return: details on the task.
        """
        session = self.Session()
        try:
            if details:
                task = session.query(Task).options(joinedload("guest"), joinedload("errors"), joinedload("tags"), joinedload("experiment"), joinedload("sample")).get(task_id)
            else:
                task = session.query(Task).get(task_id)
        except SQLAlchemyError as e:
            log.debug("Database error viewing task: {0}".format(e))
            return None
        else:
            if task:
                session.expunge(task)
        finally:
            session.close()
        return task

    def delete_task(self, task_id):
        """Delete information on a task.
        @param task_id: ID of the task to query.
        @return: operation status.
        """
        session = self.Session()
        try:
            task = session.query(Task).get(task_id)
            session.delete(task)
            session.commit()
        except SQLAlchemyError as e:
            log.debug("Database error deleting task: {0}".format(e))
            session.rollback()
            return False
        finally:
            session.close()
        return True

    def update_experiment(self, name, id=None, delta=None, timeout=None,
                          machine_name=False):
        """Update fields of an experiment.

        The updated values will be reflected when the next analysis takes
        place, e.g., the timeout is only changed for the upcoming analysis
        task.

        @param name: Experiment name.
        @param id: Experiment ID.
        @param delta: Relative time to start the next analysis.
        @param timeout: Duration of the analysis.
        @param machine_name: Machine name this experiment is bound to.
        """
        session = self.Session()
        try:
            if id is not None:
                experiment = session.query(Experiment).get(id)
            else:
                experiment = session.query(Experiment).filter_by(name=name).first()

            if delta is not None:
                experiment.delta = delta

            if timeout is not None:
                task = experiment.tasks.order_by(Task.id.desc()).first()
                task.timeout = timeout

            if machine_name is not False:
                experiment.machine_name = machine_name

            session.commit()
        except SQLAlchemyError as e:
            log.debug("Database error updating experiment: {0}".format(e))
            session.rollback()
            return False
        finally:
            session.close()
        return True

    def delete_experiment(self, experiment_id):
        """Delete experiment by identifier."""
        session = self.Session()
        try:
            experiment = session.query(Experiment).get(experiment_id)
            session.delete(experiment)
            session.commit()
        except SQLAlchemyError as e:
            log.debug("Database error deleting experiment: {0}".format(e))
            session.rollback()
            return False
        finally:
            session.close()
        return True

    def view_experiment(self, id=None, name=None, machine_name=None):
        """View experiment by id or name."""
        session = self.Session()
        try:
            experiment = session.query(Experiment)
            if id is not None:
                experiment = experiment.get(id)
            elif name is not None:
                experiment = experiment.filter_by(name=name).first()
            elif machine_name is not None:
                experiment = experiment.filter_by(machine_name=machine_name)
                experiment = experiment.first()
            else:
                log.critical("No experiment ID, name, or machine name has been provided")
                return None
        except SQLAlchemyError as e:
            log.debug("Database error viewing experiment: {0}".format(e))
            return None
        finally:
            session.close()
        return experiment

    def view_sample(self, sample_id):
        """Retrieve information on a sample given a sample id.
        @param sample_id: ID of the sample to query.
        @return: details on the sample used in sample: sample_id.
        """
        session = self.Session()
        try:
            sample = session.query(Sample).get(sample_id)
        except AttributeError:
            return None
        except SQLAlchemyError as e:
            log.debug("Database error viewing task: {0}".format(e))
            return None
        else:
            if sample:
                session.expunge(sample)
        finally:
            session.close()

        return sample

    def find_sample(self, md5=None, sha256=None):
        """Search samples by MD5.
        @param md5: md5 string
        @return: matches list
        """
        session = self.Session()
        try:
            if md5:
                sample = session.query(Sample).filter_by(md5=md5).first()
            elif sha256:
                sample = session.query(Sample).filter_by(sha256=sha256).first()
        except SQLAlchemyError as e:
            log.debug("Database error searching sample: {0}".format(e))
            return None
        else:
            if sample:
                session.expunge(sample)
        finally:
            session.close()
        return sample

    def count_samples(self):
        """Counts the amount of samples in the database."""
        session = self.Session()
        try:
            sample_count = session.query(Sample).count()
        except SQLAlchemyError as e:
            log.debug("Database error counting samples: {0}".format(e))
            return 0
        finally:
            session.close()
        return sample_count

    def view_machine(self, name):
        """Show virtual machine.
        @params name: virtual machine name
        @return: virtual machine's details
        """
        session = self.Session()
        try:
            machine = session.query(Machine).options(joinedload("tags")).filter(Machine.name == name).first()
        except SQLAlchemyError as e:
            log.debug("Database error viewing machine: {0}".format(e))
            return None
        else:
            if machine:
                session.expunge(machine)
        finally:
            session.close()
        return machine

    def view_machine_by_label(self, label):
        """Show virtual machine.
        @params label: virtual machine label
        @return: virtual machine's details
        """
        session = self.Session()
        try:
            machine = session.query(Machine).options(joinedload("tags")).filter(Machine.label == label).first()
        except SQLAlchemyError as e:
            log.debug("Database error viewing machine by label: {0}".format(e))
            return None
        else:
            if machine:
                session.expunge(machine)
        finally:
            session.close()
        return machine

    def view_errors(self, task_id):
        """Get all errors related to a task.
        @param task_id: ID of task associated to the errors
        @return: list of errors.
        """
        session = self.Session()
        try:
            errors = session.query(Error).filter_by(task_id=task_id).all()
        except SQLAlchemyError as e:
            log.debug("Database error viewing errors: {0}".format(e))
            return []
        finally:
            session.close()
        return errors
