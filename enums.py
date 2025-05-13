from enum import Enum


class UserRole(str, Enum):
    super_admin = "super_admin"
    admin = "admin"
    driver = "driver"
    user = "user"
