"""Canonical strict boundary base. Child schemas must not import package root."""
from pydantic import BaseModel,ConfigDict,model_validator


class Boundary(BaseModel):
    model_config=ConfigDict(extra='forbid',strict=True)

    @model_validator(mode='before')
    @classmethod
    def hash_shapes(cls,value):
        if isinstance(value,dict):
            if 'schema_version' in value and type(value['schema_version']) is not int:
                raise ValueError('schema_version must be an exact integer')
            ids={'id','event_id','previous_event_id','question_id','generation_binding'}
            for key,item in value.items():
                if item is None or key not in cls.model_fields: continue
                if key.endswith('_sha256') or key in ids:
                    if type(item) is not str or len(item)!=64 or any(c not in '0123456789abcdef' for c in item):
                        raise ValueError('invalid SHA256 identity: '+key)
        return value
