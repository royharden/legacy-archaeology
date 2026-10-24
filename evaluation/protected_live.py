"""T3 protected frozen live billing authority SOURCE, distinct from public T1.

No provider, crypto, SQLite, clock or fixture operation occurs on import. The
heldout authority is the exact EligibilityContext (T0 commitment, T2 freeze, T3
suite, verified custody receipts); a separately signed spend scope additionally
binds the frozen model/price/billing code/caps. T3 events use EditionRegistry's
single committed chain through fold_protected_event (registry hook owned by
edition_registry.py); until that dispatch exists every t3_* append fails closed.
Pricing has one source of truth: D7 priced_usage through public_live.BillingAdapter.
This module mints no keys or authority and makes no current vendor/price claim.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import date, datetime, timezone
from decimal import Decimal
from typing import Callable

from .artifacts import canonical, digest, is_sha
from .benchmark import ARMS, FREEZE_KEYS
from .eligibility import ReceiptVerifier, closed, hashes, text, validate_commitment, validate_freeze, validate_suite
from .public_live import BillingAdapter, money, validate_price

SCOPE_KEYS = {'schema_version', 'stage', 'action', 'edition', 'attempt_id', 'commitment_sha256',
              'freeze_sha256', 'suite_sha256', 'edition_nonce', 'nonce', 'pins', 'provider', 'model',
              'model_version', 'api_version_pin', 'billing_config_sha256', 'billing_code_sha256', 'price',
              'caps', 'not_after_utc', 'capture_root_sha256', 'registry_sha256', 'registry_head_sha256',
              'scope_sha256'}
CAP_LIMITS = {'max_input_tokens': (1, 8000), 'max_output_tokens': (1, 2000),
              'max_product_requests': (0, 3), 'max_b1_requests': (1, 1), 'max_questions': (0, 12),
              # Eight heldout variants x (B1 1 + C0/R0/R1 3 each); B0 never calls.
              'max_total_requests': (1, 80), 'price_max_age_days': (1, 30)}
PROVIDER_METHODS = ('B1', 'C0', 'R0', 'R1')


def _reserve(scope: dict) -> Decimal:
    """Conservative pre-transport reserve: full input at uncached rate plus full output."""
    caps, rates = scope['caps'], scope['price']['rates_per_million']
    return (Decimal(caps['max_input_tokens']) * money(rates['input_tokens'])
            + Decimal(caps['max_output_tokens']) * money(rates['output_tokens'])) / 1000000


def validate_scope(payload: dict, commitment: dict, freeze: dict, suite: dict, *, check_time: bool = True) -> dict:
    """Exact signed T3 spend scope against the actual sealed T0/T2/T3 identities."""
    t0 = validate_commitment(commitment)
    t2 = validate_freeze(freeze, t0)
    t3 = validate_suite(suite, t0, t2)
    value = closed(payload, SCOPE_KEYS, 'signed T3 spend scope')
    if value['stage'] != 'T3' or value['action'] != 'authorize_protected_live_spend' or t3['mode'] != 'live':
        raise ValueError('exact protected T3 live spend action required')
    for key, expected in (('edition', t0['edition']), ('commitment_sha256', t0['commitment_sha256']),
                          ('freeze_sha256', t2['freeze_sha256']), ('suite_sha256', t3['suite_sha256']),
                          ('attempt_id', t3['attempt_id']), ('edition_nonce', t2['nonce']),
                          ('capture_root_sha256', t3['capture_root_sha256'])):
        if value[key] != expected:
            raise ValueError('T3 scope names another edition/freeze/suite/attempt: ' + key)
    for name in ('provider', 'model', 'model_version', 'api_version_pin'):
        text(value[name], name, 200)
    hashes(value, ('nonce', 'billing_config_sha256', 'billing_code_sha256', 'registry_sha256', 'scope_sha256'))
    if value['registry_head_sha256'] is not None and not is_sha(value['registry_head_sha256']):
        raise ValueError('admission registry head pin must be exact or null for an empty journal')
    if value['nonce'] == value['edition_nonce']:
        raise ValueError('spend scope needs its own fresh nonce')
    closed(value['pins'], set(FREEZE_KEYS), 'T3 frozen pins')
    if value['pins'] != t2['pins']:
        raise ValueError('spend scope differs from the actual T2 frozen configuration')
    price = validate_price(value['price'], value['provider'], value['model'])
    caps = closed(value['caps'], set(CAP_LIMITS) | {'total_usd'}, 'T3 caps')
    for key, (low, high) in CAP_LIMITS.items():
        if type(caps[key]) is not int or not low <= caps[key] <= high:
            raise ValueError('invalid signed T3 token/request/question cap: ' + key)
    if money(caps['total_usd']) <= 0:
        raise ValueError('positive signed USD cap required for a live suite')
    if (t2['pins']['price_sha256'] != price['price_sha256']
            or t2['pins']['model_sha256'] != digest({'provider': value['provider'], 'model': value['model'],
                                                    'model_version': value['model_version']})
            or t2['pins']['caps_sha256'] != digest(caps)):
        raise ValueError('model/dated price/caps differ from frozen T2 pins')
    expiry = datetime.fromisoformat(value['not_after_utc'].replace('Z', '+00:00'))
    if expiry.tzinfo is None:
        raise ValueError('zoned T3 scope expiry required')
    if date.fromisoformat(price['as_of_date']) > expiry.date():
        raise ValueError('price evidence date exceeds scope validity')
    if check_time:
        now = datetime.now(timezone.utc)
        if now > expiry:
            raise ValueError('expired T3 spend scope')
        age = (now.date() - date.fromisoformat(price['as_of_date'])).days
        if not 0 <= age <= caps['price_max_age_days']:
            raise ValueError('dated price evidence is future/stale for this T3 scope')
    if value['scope_sha256'] != digest({k: v for k, v in value.items() if k != 'scope_sha256'}):
        raise ValueError('T3 scope hash mismatch')
    return value


def _live_calls(state: dict):
    public = state.get('t1')
    if public is not None:
        for attempt in public['attempts'].values():
            yield from attempt['calls'].values()
    protected = state.get('t3')
    if protected is not None:
        yield from protected['calls'].values()


def assert_no_unknown_live_liability(events: list[dict]) -> None:
    """Any reserved/unknown T1 or T3 call blocks further live trials in every edition."""
    from .edition_registry import EditionRegistry
    for edition in sorted({event['edition'] for event in events}):
        state = EditionRegistry._state(events, edition)
        if any(call['status'] != 'known' for call in _live_calls(state)):
            raise ValueError('unresolved live liability/single-flight reserve blocks additional live calls')


def _arm_key(variant_id: str, method: str) -> str:
    return digest({'variant_id': variant_id, 'method': method})


def fold_protected_event(state: dict, event: dict) -> bool:
    """Pure fold inside the same EditionRegistry chain; False = standard handling continues.

    The registry dispatches EVERY event of the edition here (before its standard
    handling), so a live attempt_started without an admitted T3 scope is refused
    even when no t3_* event exists yet.
    """
    kind, value = event['event_type'], event['payload']
    protected = state.get('t3')
    if kind == 'attempt_started':
        suite = value.get('suite') if isinstance(value, dict) else None
        if isinstance(suite, dict) and suite.get('mode') == 'live':
            if (protected is None or suite.get('suite_sha256') != protected['scope']['suite_sha256']
                    or value.get('authority_sha256') != protected['suite_authority_sha256']):
                raise ValueError('live heldout attempt requires the admitted T3 spend scope and its pinning suite authority')
        elif protected is not None:
            raise ValueError('admitted T3 scope binds a live suite')
        return False
    if kind == 't3_scope_admitted':
        closed(value, {'scope', 'scope_receipt_sha256', 'suite_authority_sha256'}, 'T3 scope admission')
        if (protected is not None or state['commitment'] is None or state['freeze'] is None
                or state['attempt'] is not None or state['exposed'] or state['retired']):
            raise ValueError('T3 scope admission needs one frozen, unconsumed, unexposed edition')
        hashes(value, ('scope_receipt_sha256', 'suite_authority_sha256'))
        scope = value['scope']
        if not isinstance(scope, dict) or scope.get('freeze_sha256') != state['freeze']['freeze_sha256']:
            raise ValueError('T3 scope names another freeze')
        # Signatures/time are checked by the live context at admission; replay folds are timeless.
        state['t3'] = {'scope': deepcopy(scope), 'scope_receipt_sha256': value['scope_receipt_sha256'],
                       'suite_authority_sha256': value['suite_authority_sha256'], 'calls': {}}
        return True
    if kind.startswith('t3_') and protected is None:
        raise ValueError('T3 mutation precedes scope admission')
    if protected is None:
        return False
    scope = protected['scope']
    attempt = state['attempt']
    if kind == 'arm_finished':
        if value.get('method') == 'B1' and value.get('status') == 'completed':
            calls = [c for c in protected['calls'].values()
                     if c['variant_id'] == value.get('variant_id') and c['method'] == 'B1']
            if len(calls) != 1 or calls[0]['status'] != 'known':
                raise ValueError('complete T3 B1 needs exactly one accounted request, never repair/no-output')
        if value.get('status') == 'completed' and any(
                c.get('overrun') and c['variant_id'] == value.get('variant_id') and c['method'] == value.get('method')
                for c in protected['calls'].values()):
            raise ValueError('an arm with a cap-overrun call cannot claim completed')
        return False
    if kind == 'attempt_finished':
        if value.get('status') == 'completed' and any(c['status'] != 'known' or c.get('overrun')
                                                      for c in protected['calls'].values()):
            raise ValueError('incomplete/unknown-cost T3 suite cannot claim complete')
        return False
    if kind == 't3_liability_reconciled':
        closed(value, {'attempt_id', 'call_id', 'known_cost', 'usage', 'billing_capture', 'authority_sha256'},
               'T3 billing reconciliation')
        call = protected['calls'].get(value['call_id'])
        if value['attempt_id'] != scope['attempt_id'] or call is None or call['status'] == 'known':
            raise ValueError('no unknown/reserved T3 liability to reconcile')
        money(value['known_cost'])
        hashes(value, ('authority_sha256',))
        call.update(status='known', known_cost=value['known_cost'], usage=deepcopy(value['usage']),
                    billing_capture=deepcopy(value['billing_capture']))
        return True
    if not kind.startswith('t3_'):
        return False
    if kind == 't3_request_settled':
        # An in-flight call must settle truthfully even if the edition was exposed
        # or the attempt ended meanwhile; only the exact reserved call is required.
        closed(value, {'attempt_id', 'call_id', 'cost_status', 'known_cost', 'usage', 'reply_sha256',
                       'billing_receipt', 'pricing_code_sha256', 'error_type', 'overrun'}, 'T3 usage receipt')
        call = protected['calls'].get(value['call_id'])
        if type(value['overrun']) is not bool or (value['overrun'] and value['cost_status'] != 'known'):
            raise ValueError('overrun mark applies only to a known settled cost')
        if (value['attempt_id'] != scope['attempt_id'] or call is None or call['status'] != 'reserved'
                or value['cost_status'] not in ('known', 'unknown')):
            raise ValueError('T3 usage receipt lacks unique reserved attempt')
        if value['cost_status'] == 'known':
            money(value['known_cost'])
            receipt = value['billing_receipt']
            if (not isinstance(receipt, dict) or receipt.get('raw_usage') != value['usage']
                    or receipt.get('cost_known') is not True or receipt.get('cost_usd') != value['known_cost']
                    or receipt.get('evaluation_phase') != 'T3'
                    or receipt.get('evaluation_authority_sha256') != scope['scope_sha256']
                    or value['pricing_code_sha256'] != scope['billing_code_sha256']
                    or receipt.get('receipt_sha256') != digest({k: v for k, v in receipt.items() if k != 'receipt_sha256'})):
                raise ValueError('known T3 cost must retain the actual pinned D7 billing receipt')
        elif value['known_cost'] is not None:
            raise ValueError('unknown T3 cost cannot be fabricated zero')
        call.update(status=value['cost_status'], known_cost=value['known_cost'], usage=deepcopy(value['usage']),
                    billing_receipt=deepcopy(value['billing_receipt']), reply_sha256=value['reply_sha256'],
                    error_type=value['error_type'], overrun=value['overrun'])
        return True
    if (attempt is None or attempt['status'] != 'running' or value.get('attempt_id') != scope['attempt_id']
            or attempt['suite']['attempt_id'] != scope['attempt_id'] or state['exposed'] or state['retired']):
        raise ValueError('no active exact protected T3 attempt')
    caps = scope['caps']
    if kind == 't3_request_reserved':
        closed(value, {'attempt_id', 'variant_id', 'method', 'call_id', 'request_no', 'prompt_sha256',
                       'source_sha256', 'input_tokens', 'output_limit', 'reserved_usd'}, 'T3 request reservation')
        if value['method'] not in PROVIDER_METHODS or value['variant_id'] not in attempt['suite']['variant_ids']:
            raise ValueError('T3 request names an arm that makes no provider call')
        arm = attempt['arms'].get(_arm_key(value['variant_id'], value['method']))
        if arm is None or arm['status'] != 'running':
            raise ValueError('request outside active unique T3 arm')
        if value['call_id'] in protected['calls'] or any(c['status'] != 'known' for c in protected['calls'].values()):
            raise ValueError('request replay or unresolved/unknown single-flight liability')
        count = sum(c['variant_id'] == value['variant_id'] and c['method'] == value['method']
                    for c in protected['calls'].values())
        maximum = caps['max_b1_requests'] if value['method'] == 'B1' else caps['max_product_requests']
        if (type(value['request_no']) is not int or count >= maximum or value['request_no'] != count + 1
                or len(protected['calls']) >= caps['max_total_requests']):
            raise ValueError('T3 per-arm/attempt request cap exhausted; no repair beyond cap')
        if (type(value['input_tokens']) is not int or not 0 <= value['input_tokens'] <= caps['max_input_tokens']
                or value['output_limit'] != caps['max_output_tokens']):
            raise ValueError('T3 preflight token cap mismatch')
        hashes(value, ('call_id', 'prompt_sha256', 'source_sha256'))
        reserve = _reserve(scope)
        spent = sum((money(c['known_cost']) for c in protected['calls'].values()), Decimal(0))
        if money(value['reserved_usd']) != reserve or spent + reserve > money(caps['total_usd']):
            raise ValueError('known T3 total plus conservative reserve exceeds signed cap')
        protected['calls'][value['call_id']] = {**deepcopy(value), 'status': 'reserved', 'known_cost': None, 'usage': None}
    else:
        raise ValueError('unknown T3 event')
    return True


@dataclass(frozen=True)
class ProtectedLiveContext:
    """Exact heldout custody authority plus a separately signed T3 spend scope."""
    eligibility: object
    scope_receipt: dict
    billing: BillingAdapter

    def __post_init__(self):
        from .edition_registry import EligibilityContext
        from .public_live import PublicLiveContext
        if type(self.eligibility) is PublicLiveContext:
            raise ValueError('public T1 authority can never authorize protected T3 spend')
        if type(self.eligibility) is not EligibilityContext or type(self.billing) is not BillingAdapter:
            raise ValueError('concrete EligibilityContext and pinned D7 billing adapter required')

    @property
    def registry(self):
        return self.eligibility.registry

    @property
    def edition(self) -> str:
        return self.eligibility.commitment['edition']

    def scope_sha256(self) -> str:
        return digest(self.scope_receipt)

    def _scope(self, *, check_time: bool, billing: bool = True) -> dict:
        verifier: ReceiptVerifier = self.eligibility.verifier
        scope = validate_scope(verifier.verify(self.scope_receipt, 'run_owner'), self.eligibility.commitment,
                               self.eligibility.freeze, self.eligibility.suite, check_time=check_time)
        if scope['registry_sha256'] != digest(str(self.registry.path)):
            raise ValueError('T3 scope names a different edition registry')
        if scope['capture_root_sha256'] != digest(str(self.registry.store.root)):
            raise ValueError('T3 scope names a different capture root')
        envelope = {'schema_version': 1, 'kind': 'signed_evidence', 'payload': self.scope_receipt}
        self.registry.store.get({'sha256': digest(envelope), 'kind': 'signed_evidence'})
        if billing:
            self.billing.validate(self._billing_view(scope))
            if self.billing.config['api_version_pin'] != scope['api_version_pin']:
                raise ValueError('billing API version pin differs from signed T3 scope')
        return scope

    def _suite_authority_pin(self) -> str:
        """The suite authority must pin exactly this spend envelope; returns its own envelope hash."""
        suite_authority = self.eligibility.verifier.verify(self.eligibility.authority_receipt, 'run_owner')
        if suite_authority['spend_authority_sha256'] != self.scope_sha256():
            raise ValueError('suite authority does not pin this exact T3 spend scope')
        return digest(self.eligibility.authority_receipt)

    def _admitted(self, scope: dict) -> dict:
        protected = self.registry.state(self.edition).get('t3')
        if (protected is None or protected['scope'] != scope or protected['scope_receipt_sha256'] != self.scope_sha256()
                or protected['suite_authority_sha256'] != self._suite_authority_pin()):
            raise ValueError('T3 spend scope not admitted or differs from the admitted scope')
        return protected

    @staticmethod
    def _billing_view(scope: dict) -> dict:
        """Key-compatible view for BillingAdapter; authority_sha256 is the T3 scope hash."""
        return {'provider': scope['provider'], 'model': scope['model'], 'model_version': scope['model_version'],
                'billing_config_sha256': scope['billing_config_sha256'],
                'billing_code_sha256': scope['billing_code_sha256'], 'price': scope['price'],
                'caps': scope['caps'], 'authority_sha256': scope['scope_sha256']}

    def validate(self, *, check_time: bool = True) -> dict:
        """Custody + suite authority + spend scope + admitted registry state."""
        self.eligibility.validate()
        scope = self._scope(check_time=check_time)
        self._admitted(scope)
        return scope

    def admit(self, *, request_id: str, expected_head: str | None):
        """Record the scope before the attempt starts; the head pin proves signing freshness."""
        self.eligibility.validate()
        scope = self._scope(check_time=True)
        suite_authority_sha256 = self._suite_authority_pin()
        if scope['registry_head_sha256'] != expected_head:
            raise ValueError('T3 scope was signed against another registry head')
        events = self.registry.events()
        for event in events:
            payload = event['payload']
            if event['event_type'] == 't1_attempt_started' and (
                    payload.get('nonce') == scope['nonce'] or payload.get('authority_sha256') == scope['scope_sha256']):
                raise ValueError('public T1 authority/nonce cannot be reused as T3 spend scope')
            if event['event_type'] == 't3_scope_admitted' and payload['scope']['nonce'] == scope['nonce']:
                raise ValueError('T3 scope nonce replay')
        assert_no_unknown_live_liability(events)
        return self.registry._append(self.edition, 't3_scope_admitted',
                                     {'scope': scope, 'scope_receipt_sha256': self.scope_sha256(),
                                      'suite_authority_sha256': suite_authority_sha256},
                                     request_id=request_id, expected_head=expected_head)

    def trusted_authority(self) -> dict:
        """Trusted T3 view for D7 provider_port; carries no T1 authority or signing material."""
        scope = self.validate()
        return {**self._billing_view(scope), 'attempt_id': scope['attempt_id'], 'evaluation_phase': 'T3',
                'api_version_pin': scope['api_version_pin']}

    def provider_port(self, inner: Callable[[dict], dict], cases, count_tokens: Callable[[str], int]):
        """cases: the declared heldout VariantCases; keyed by their exact provider-visible input."""
        from .runner import _prompt_input
        mapped = {}
        for item in cases:
            key = digest(_prompt_input(item.visible))
            if key in mapped:
                raise ValueError('two heldout variants share one provider-visible input; ambiguous T3 attribution')
            mapped[key] = item
        if not mapped or any(item.variant_id not in self.eligibility.suite['variant_ids'] or item.split != 'heldout'
                             or item.edition != self.edition for item in mapped.values()):
            raise ValueError('T3 port admits only declared heldout variants of this edition')
        return ProtectedProviderPort(self, inner, mapped, count_tokens)

    def reconcile_liability(self, signed_receipt: dict, *, request_id: str):
        # No custody/exposure gate: an unknown liability must stay reconcilable after
        # the edition is exposed/retired, or it would block every later live call.
        # Nor a pricing-code pin: reconciliation prices nothing, and a later D7 pricing
        # upgrade must not make an old unknown liability unreconcilable.
        scope = self._scope(check_time=False, billing=False)
        self._admitted(scope)
        receipt = closed(self.eligibility.verifier.verify(signed_receipt, 'run_owner'),
            {'schema_version', 'action', 'edition', 'attempt_id', 'call_id', 'scope_sha256', 'billing_capture'},
            'signed T3 billing reconciliation')
        if (receipt['action'] != 'reconcile_protected_liability' or receipt['edition'] != self.edition
                or receipt['attempt_id'] != scope['attempt_id'] or receipt['scope_sha256'] != scope['scope_sha256']):
            raise ValueError('wrong T3 liability reconciliation authority')
        bill = closed(self.registry.store.get(receipt['billing_capture'], kind='billing_observation'),
            {'schema_version', 'edition', 'attempt_id', 'call_id', 'provider', 'model', 'billed_usd',
             'usage', 'observed_at', 'provider_receipt'}, 'actual T3 billing capture')
        if (any(bill[key] != receipt[key] for key in ('edition', 'attempt_id', 'call_id'))
                or bill['provider'] != scope['provider'] or bill['model'] != scope['model']):
            raise ValueError('billing effect does not bind the unknown T3 call')
        money(bill['billed_usd']); text(bill['observed_at'], 'billing observation time')
        call = self.registry.state(self.edition)['t3']['calls'].get(receipt['call_id'])
        native = bill['provider_receipt']
        if (call is None or not isinstance(native, dict) or native.get('status') != 'reconciled'
                or native.get('cost_known') is not True or native.get('cost_usd') != bill['billed_usd']
                or native.get('raw_usage') != bill['usage'] or native.get('evaluation_phase') != 'T3'
                or native.get('evaluation_authority_sha256') != scope['scope_sha256']
                or native.get('gateway_prompt_sha256') != call['prompt_sha256']
                or native.get('source_sha256') != call['source_sha256']
                or native.get('evaluator_method') != call['method']
                or not is_sha(native.get('billing_evidence_sha256'))
                or native.get('receipt_sha256') != digest({k: v for k, v in native.items() if k != 'receipt_sha256'})):
            raise ValueError('actual D7 reconciled T3 receipt must establish the billing fact')
        return self.registry._append(self.edition, 't3_liability_reconciled',
            {'attempt_id': scope['attempt_id'], 'call_id': receipt['call_id'], 'known_cost': bill['billed_usd'],
             'usage': bill['usage'], 'billing_capture': receipt['billing_capture'],
             'authority_sha256': digest(signed_receipt)},
            request_id=request_id, expected_head=self.registry.head)


@dataclass(frozen=True)
class ProtectedProviderPort:
    """RunnerPorts.provider for a protected live suite: reserve -> D7 transport -> settle.

    The RequestGateway already enforces single flight and its own per-arm budget;
    this port adds the signed-scope caps, durable reservation before transport and
    native billing settlement. Unknown/mismatched cost settles 'unknown' and raises,
    which fails the arm and blocks every later live reservation until reconciled.
    """
    context: ProtectedLiveContext
    inner: Callable[[dict], dict]
    cases: dict
    count_tokens: Callable[[str], int]

    def __call__(self, request: dict) -> dict:
        scope = self.context.validate()
        caps = scope['caps']
        if (not isinstance(request, dict) or request.get('mode') != 'live' or request.get('allow_retries') is not False
                or request.get('method') not in PROVIDER_METHODS
                or (request['method'] == 'B1' and request.get('allow_repairs') is not False)):
            raise ValueError('exact live no-retry evaluator request required for T3')
        prompt = request.get('prompt')
        visible = prompt.get('input') if isinstance(prompt, dict) else None
        case = self.cases.get(digest(visible)) if isinstance(visible, dict) else None
        source_sha = visible.get('source_sha256') if case is not None else None
        if case is None or case.split != 'heldout' or case.edition != self.context.edition:
            raise ValueError('T3 request does not name one declared heldout case')
        if request.get('prompt_sha256') != digest(prompt):
            raise ValueError('T3 request prompt hash mismatch')
        tokens = self.count_tokens(canonical(prompt).decode('utf-8'))
        if type(tokens) is not int or not 0 <= tokens <= caps['max_input_tokens']:
            raise ValueError('T3 input token preflight exceeds signed cap')
        method = request['method']
        call_id = digest({'scope': scope['scope_sha256'], 'variant': case.variant_id, 'method': method,
                          'request_no': request.get('attempt'), 'prompt_sha256': request['prompt_sha256']})
        reservation = {'attempt_id': scope['attempt_id'], 'variant_id': case.variant_id, 'method': method,
                       'call_id': call_id, 'request_no': request.get('attempt'),
                       'prompt_sha256': request['prompt_sha256'], 'source_sha256': source_sha,
                       'input_tokens': tokens, 'output_limit': caps['max_output_tokens'],
                       'reserved_usd': str(_reserve(scope))}
        registry = self.context.registry
        receipt = registry._append(self.context.edition, 't3_request_reserved', reservation,
                                   request_id='t3-reserve:' + call_id, expected_head=registry.head)
        if not receipt.newly_created:
            raise ValueError('historical T3 reservation cannot call the provider again')
        outbound = {**deepcopy(request), 'max_input_tokens': caps['max_input_tokens'],
                    'max_output_tokens': caps['max_output_tokens'], 'provider': scope['provider'],
                    'model': scope['model'], 'price_sha256': scope['price']['evidence_sha256'],
                    'evaluation_phase': 'T3', 'evaluation_authority_sha256': scope['scope_sha256']}
        try:
            reply = self.inner(outbound)
        except BaseException as exc:
            # Timeout/transport loss: liability unknown until signed native billing evidence.
            self._settle(scope, call_id, None, type(exc).__name__)
            raise
        error_type = None
        try:
            cost = self.context.billing.price(reply, self.context._billing_view(scope), request['prompt_sha256'],
                                              source_sha, method, phase='T3')
        except Exception as exc:
            # A raising pricing check must still settle the reservation, never strand it.
            cost, error_type = None, type(exc).__name__
        # The true known cost is recorded with a durable overrun mark when it exceeds the
        # per-call reserve or signed token caps; the arm then fails (and the registry refuses
        # completion even if an adapter swallows the error). Later reservations see actual spend.
        usage = reply.get('usage') if isinstance(reply, dict) and isinstance(reply.get('usage'), dict) else {}
        overrun = cost is not None and (money(cost) > _reserve(scope) or any(
            type(usage.get(name)) is int and usage[name] > caps['max_' + name] for name in ('input_tokens', 'output_tokens')))
        if self._settle(scope, call_id, reply, error_type, cost, overrun) != 'known':
            raise ValueError('T3 model/price/usage mismatch or unknown liability; future calls refused')
        if overrun:
            raise T3OverrunError(cost)
        return {**reply, 'cost_status': 'known', 'known_cost': cost}

    def _settle(self, scope, call_id, reply, error_type, cost=None, overrun=False):
        registry = self.context.registry
        payload = {'attempt_id': scope['attempt_id'], 'call_id': call_id,
                   'cost_status': 'known' if cost is not None else 'unknown', 'known_cost': cost,
                   'usage': None, 'reply_sha256': None, 'billing_receipt': None,
                   'pricing_code_sha256': scope['billing_code_sha256'], 'error_type': error_type,
                   'overrun': bool(overrun and cost is not None)}
        try:
            if isinstance(reply, dict):
                payload['usage'] = deepcopy(reply.get('usage'))
                payload['billing_receipt'] = deepcopy(reply.get('provider_receipt'))
            payload['reply_sha256'] = digest(reply) if reply is not None else None
            digest(payload)
        except (TypeError, ValueError):
            # Unserializable provider output: settle unknown without the unhashable parts.
            payload.update(cost_status='unknown', known_cost=None, usage=None, billing_receipt=None,
                           reply_sha256=None, overrun=False, error_type=error_type or 'UnserializableReply')
        registry._append(self.context.edition, 't3_request_settled', payload,
                         request_id='t3-settle:' + call_id, expected_head=registry.head)
        return payload['cost_status']


class T3OverrunError(ValueError):
    """Known cost was settled truthfully but exceeded the per-call reserve or signed token caps.

    The gateway still records this attempt as cost_status 'unknown' (runner.py is not
    T3-aware); the registry's t3 call record holds the authoritative known cost.
    """
    def __init__(self, known_cost: str):
        super().__init__('T3 call exceeded its signed reserve/token caps; arm failed after truthful settlement')
        self.known_cost = known_cost


def require_protected_ports(ports, eligibility) -> None:
    """Runner hook (D4 runner.py): a live heldout suite may call providers only via this T3 port.

    Call before EligibilityContext.begin() and before each live heldout arm. Admission
    alone cannot detect raw provider wiring; this check closes that bypass.
    """
    provider = getattr(ports, 'provider', None)
    if (type(provider) is not ProtectedProviderPort or provider.context.eligibility is not eligibility):
        raise ValueError('live heldout suite requires the protected T3 provider port bound to this eligibility')
    provider.context.validate()


def question_cap(ports) -> int | None:
    """Signed T3 max_questions for the runner's heldout question check (None when not T3)."""
    provider = getattr(ports, 'provider', None)
    if type(provider) is not ProtectedProviderPort:
        return None
    return provider.context.validate(check_time=False)['caps']['max_questions']
