from rest_framework import permissions


class IsOwnerOrReadOnly(permissions.BasePermission):
    """
    Custom permissions to only allow owners of an object to edit it.
    """

    # Read permissions are allowed to any request,
    # so we will always allow GET, HEAD or OPTIONS request
    def has_object_permission(self, request, view, obj):
        # if request.method in permissions.SAFE_METHODS:
        #     return True
        print('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')
        result = obj.seller == request.user
        print(result)
        return obj.owner == request.user

