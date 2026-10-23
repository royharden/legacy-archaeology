"""Current-generation caches recover solely from D5's committed SQLite snapshot."""
from la.contracts import digest, validate_generation
from .artifacts import identity, immutable, within, read, pointer
from .storage import pointer_token


def current_generation(run, batch, store):
    state=store.current_state()
    if state['state_token']!=digest({k:v for k,v in state.items() if k!='state_token'}):
        raise ValueError('ruling authority snapshot token mismatch')
    if state['status']=='unbound':
        if within(run,'current-generation.json').exists():
            raise ValueError('generation cache has no committed ruling authority')
        return None
    if state['status']=='legacy_binding_requires_rebind':
        matches=[]
        for index,path in enumerate(run.iterdir()):
            if index>=512: raise ValueError('legacy generation recovery inventory limit')
            if not path.name.startswith('generation-') or not path.name.endswith('.json'): continue
            key=identity(path.name[len('generation-'):-len('.json')])
            value=validate_generation(read(within(run,path.name,exists=True),canonical_required=True))
            if value['generation_sha256']!=key: raise ValueError('archive generation filename mismatch')
            if digest(value)==state['generation_binding']: matches.append(value)
        if len(matches)!=1: raise ValueError('legacy binding requires one exact retained generation; no recency guess')
        if any(matches[0][key]!=batch[key] for key in ('source_sha256','framing_sha256','brief_sha256')):
            raise ValueError('legacy generation dependency mismatch')
        state=store.bind_generation(matches[0],expected_state_token=state['state_token'])
    if state['status']!='bound' or state['generation'] is None:
        raise ValueError('no recoverable committed generation')
    generation=validate_generation(state['generation'])
    key=identity(generation['generation_sha256'])
    if digest(generation)!=state['generation_binding'] or any(generation[k]!=batch[k] for k in ('source_sha256','framing_sha256','brief_sha256')):
        raise ValueError('committed generation dependency mismatch')
    # Missing archive after an interrupted cache write can be rebuilt from the
    # actual stored generation. Existing divergent frozen bytes refuse repair.
    immutable(within(run,'generation-'+key+'.json'),generation)
    index=within(run,'current-generation.json')
    pointer(index,dict(generation_sha256=key,generation_binding=state['generation_binding'],
                       generation_epoch=state['generation_epoch']),expected=pointer_token(index))
    return generation
