from abc import ABC, abstractmethod
from typing import Optional


class Commentable(ABC):
    @property
    @abstractmethod
    def comment(self) -> Optional[str]:
        raise NotImplementedError

    @comment.setter
    def comment(self, value: Optional[str]):
        raise NotImplementedError

    @comment.deleter
    def comment(self):
        raise NotImplementedError

    @property
    @abstractmethod
    def repeatable_comment(self) -> Optional[str]:
        raise NotImplementedError

    @repeatable_comment.setter
    def repeatable_comment(self, value: Optional[str]):
        raise NotImplementedError

    @repeatable_comment.deleter
    def repeatable_comment(self):
        raise NotImplementedError

    @property
    def has_comment(self) -> bool:
        return ((self.comment != "" and self.comment is not None)
                or (self.repeatable_comment != "" and self.repeatable_comment is not None))
