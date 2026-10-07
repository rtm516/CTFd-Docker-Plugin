"""
Upgrade from the original single-file plugin.

The original plugin kept container challenges in `container_challenge_model`
and its settings in `container_settings_model`. This copies them into the
current tables when the plugin loads, so challenges created before the upgrade
keep working. Rows that already exist in the current tables are left alone, so
it is safe to run on every start.

Not carried over: running containers (they are not tracked by the new tables;
stop them before upgrading) and per-challenge volumes (no longer supported).
"""
import logging

from sqlalchemy import MetaData, Table, inspect, select, text

from CTFd.models import Challenges, Flags, db

from .models import ContainerChallenge, ContainerConfig

logger = logging.getLogger(__name__)

OLD_CHALLENGE_TABLE = "container_challenge_model"
OLD_SETTINGS_TABLE = "container_settings_model"

CONNECTION_TYPES = {"web": "http", "web-ssh": "http", "tcp": "tcp", "ssh": "ssh"}

#: Old setting key -> new config key
SETTINGS = {
    "docker_base_url": "docker_socket",
    "docker_hostname": "connection_host",
    "container_expiration": "default_timeout",
    "container_maxcpu": "max_cpu",
    "max_containers": "container_max_concurrent_count",
}

#: Columns added to the challenge table after it was first released
ADDED_COLUMNS = ("ssh_username", "ssh_password")


def run():
    """Bring the database up to date. Call after create_all()."""
    tables = inspect(db.engine).get_table_names()
    _add_missing_columns()
    if OLD_SETTINGS_TABLE in tables:
        _migrate_settings()
    if OLD_CHALLENGE_TABLE in tables:
        _migrate_challenges()


def _add_missing_columns():
    """create_all() never alters an existing table, so add new columns here."""
    table = ContainerChallenge.__table__.name
    existing = {column["name"] for column in inspect(db.engine).get_columns(table)}
    for name in ADDED_COLUMNS:
        if name not in existing:
            db.session.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} TEXT"))
            logger.info("Added column %s.%s", table, name)
    db.session.commit()


def _migrate_settings():
    """Copy old settings, but only into keys that have not been set yet."""
    settings = _reflect(OLD_SETTINGS_TABLE)
    rows = db.session.execute(select(settings.c.key, settings.c.value)).all()
    old = {key: value for key, value in rows if value not in (None, "")}

    new = {SETTINGS[key]: value for key, value in old.items() if key in SETTINGS}
    if old.get("container_maxmemory"):
        new["max_memory"] = f"{old['container_maxmemory']}m"

    for key, value in new.items():
        if ContainerConfig.get(key) is None:
            ContainerConfig.set(key, value)
            logger.info("Migrated setting %s", key)


def _migrate_challenges():
    table = ContainerChallenge.__table__
    columns = {column.name: column for column in table.columns}
    migrated = {row[0] for row in db.session.execute(select(table.c.id))}
    old_rows = db.session.execute(select(_reflect(OLD_CHALLENGE_TABLE))).mappings().all()
    migrated_now = []

    for old in old_rows:
        if old["id"] in migrated:
            continue
        challenge = Challenges.query.get(old["id"])
        if challenge is None:
            continue

        port = old.get("port") or 80
        values = dict(
            id=old["id"],
            image=old.get("image") or "",
            internal_port=port,
            internal_ports=str(port),
            command=old.get("command") or "",
            connection_type=CONNECTION_TYPES.get(old.get("connection_type"), "http"),
            connection_info="",
            pids_limit=100,
            ssh_username=old.get("ssh_username"),
            ssh_password=old.get("ssh_password"),
            **_flag_fields(old),
            **_scoring_fields(challenge),
        )
        db.session.execute(table.insert().values({columns[name]: value for name, value in values.items()}))
        logger.info("Migrated container challenge %s (%s)", challenge.id, challenge.name)
        migrated_now.append(challenge.id)

    db.session.commit()

    # Bring decaying challenges' values in line with their current solve count
    from . import ContainerChallengeType

    db.session.expire_all()
    for challenge_id in migrated_now:
        ContainerChallengeType.calculate_value(ContainerChallenge.query.get(challenge_id))


def _reflect(name):
    return Table(name, MetaData(), autoload_with=db.engine)


def _flag_fields(old):
    prefix = old.get("flag_prefix") or ""
    suffix = old.get("flag_suffix") or ""
    if old.get("flag_mode") == "random":
        return dict(
            flag_mode="random",
            flag_prefix=prefix,
            flag_suffix=suffix,
            random_flag_length=old.get("random_flag_length") or 10,
        )

    # Static flags used to be prefix + the challenge's CTFd flag + suffix
    flag = Flags.query.filter_by(challenge_id=old["id"]).first()
    content = flag.content if flag else ""
    return dict(flag_mode="static", flag_prefix=prefix + content + suffix, flag_suffix="", random_flag_length=0)


def _scoring_fields(challenge):
    """
    Keep decay only for challenges set to CTFd's Linear or Logarithmic scoring
    function. The plugin now does the decay itself, so CTFd's own function is
    reset to static to stop both applying.

    Older versions of the plugin decayed every challenge with an initial value,
    even static ones, so a static challenge goes back to its initial value.
    """
    function = getattr(challenge, "function", None)
    initial = getattr(challenge, "initial", None)
    minimum = getattr(challenge, "minimum", None)
    decay = getattr(challenge, "decay", None)

    if function in ("linear", "logarithmic") and None not in (initial, minimum, decay) and decay > 0:
        challenge.function = "static"
        return dict(initial=int(initial), minimum=int(minimum), decay=int(decay), decay_function=function)

    if initial is not None:
        challenge.value = int(initial)
    return dict(initial=challenge.value, minimum=0, decay=0, decay_function="logarithmic")
