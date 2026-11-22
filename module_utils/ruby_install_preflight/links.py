"""Publish a fully inspected set of links without replacing existing names."""
import os
import stat

from .state import Stop, identity


class LinkCreationError(Stop):
    def __init__(self, reason, created, not_created):
        super().__init__(reason)
        self.created = list(created)
        self.not_created = list(not_created)


def create_links(plan):
    if not plan.missing:
        return []
    obs = plan.observation
    created = []
    try:
        obs.recheck()
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        directory = os.open(plan.directory, flags)
        try:
            if identity(os.fstat(directory)) != identity(obs.stat(plan.directory)):
                raise Stop("LINK_STATE_UNCERTAIN: public directory changed before publication")
            for name in plan.missing:
                obs.recheck()
                source = str(plan.prefix / "bin" / name)
                os.symlink(source, name, dir_fd=directory)
                created.append(name)
                entry = os.stat(name, dir_fd=directory, follow_symlinks=False)
                if not stat.S_ISLNK(entry.st_mode) or os.readlink(name, dir_fd=directory) != source:
                    raise Stop("LINK_STATE_UNCERTAIN: new public link changed for " + name)
                # Update only the previously absent entry this invocation just created.
                obs.seen[plan.directory / name] = identity(entry)
            obs.recheck()
        finally:
            os.close(directory)
    except (OSError, Stop) as exc:
        if isinstance(exc, FileExistsError):
            reason = "LINK_CONFLICT: a destination appeared during publication"
        elif isinstance(exc, OSError):
            reason = "LINK_CREATION_FAILED: " + str(exc)
        else:
            reason = str(exc)
        raise LinkCreationError(reason, created, plan.missing[len(created):]) from exc
    return created
