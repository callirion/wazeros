import csv,io,re,itertools
from decimal import Decimal,InvalidOperation,ROUND_HALF_UP
from datetime import date
from fastapi import HTTPException
CURRENCIES={'USD','EUR','GBP','MAD','CAD','AUD','JPY','CHF','AED','SAR'}
FIELDS=['id','label','amount','currency','date','status','received_amount','received_date','last_activity']
def parse_csv(content,mapping):
    if len(content.encode('utf-8'))>2_000_000:raise HTTPException(413,'CSV limit is 2 MB')
    reader=csv.DictReader(io.StringIO(content.lstrip('\ufeff')))
    headers=reader.fieldnames or []
    if not headers or len(headers)>60 or len(set(headers))!=len(headers):raise HTTPException(422,'CSV needs unique headers, at most 60 columns')
    if any(len(h)>120 for h in headers):raise HTTPException(422,'Header too long')
    if not mapping:return {'headers':headers,'sample':list(itertools.islice(reader,5)),'rows':[],'errors':[]}
    if any(mapping.get(k) not in headers for k in ['id','label','amount','currency','date','status']):raise HTTPException(422,'Map all required columns')
    rows=[];errors=[];seen=set()
    for line,row in enumerate(reader,2):
        if line>5001:raise HTTPException(413,'CSV limit is 5,000 rows')
        try:
            r={k:(row.get(mapping.get(k,'')) or '').strip() for k in FIELDS}
            if not r['id'] or len(r['id'])>120 or not r['label'] or len(r['label'])>120:raise ValueError('ID and label must be 1-120 characters')
            if r['id'] in seen:raise ValueError('Duplicate ID')
            if r['currency'] not in CURRENCIES:raise ValueError('Unsupported currency')
            if r['status'].lower() not in {'won','open','lost'}:raise ValueError('Status must be won, open or lost')
            r['status']=r['status'].lower()
            for k in ['amount','received_amount']:
                v=Decimal(r[k] or '0')
                if not v.is_finite() or v<0 or v>Decimal('999999999999.99') or v.as_tuple().exponent < -2:raise ValueError('Amounts must be nonnegative decimals with at most 2 decimal places')
                r[k]=str(v.quantize(Decimal('.01')))
            for k in ['date','received_date','last_activity']:
                if r[k]:
                    if not re.fullmatch(r'\d{4}-\d{2}-\d{2}',r[k]):raise ValueError('Dates must be YYYY-MM-DD')
                    d=date.fromisoformat(r[k])
                    if d>date.today():raise ValueError('Dates cannot be in the future')
            if Decimal(r['received_amount'])>0 and not r['received_date']:raise ValueError('Received amount needs received date')
            if Decimal(r['received_amount'])>Decimal(r['amount']):raise ValueError('Received amount exceeds opportunity amount')
            seen.add(r['id']);rows.append(r)
        except (ValueError,InvalidOperation,TypeError):errors.append({'line':line,'message':'Invalid ID, duplicate, amount, currency, status or date. Check the template.'})
    return {'headers':headers,'sample':[],'rows':rows,'errors':errors,'accepted':len(rows),'rejected':len(errors)}
def amount(v):return Decimal(str(v or '0')).quantize(Decimal('.01'))
def fee(v):return (amount(v)*Decimal('.10')).quantize(Decimal('.01'),rounding=ROUND_HALF_UP)
def summarize(rows,start,end,currency,claims=None):
    if start>end:raise HTTPException(422,'Start date must not follow end date')
    if (end-start).days>3660:raise HTTPException(422,'Maximum report window is 10 years')
    relevant=[r for r in rows if r['currency']==currency]
    won=sum((amount(r['amount']) for r in relevant if r['status']=='won' and start.isoformat()<=r['date']<=end.isoformat()),Decimal(0))
    receipts=sum((amount(r.get('received_amount')) for r in relevant if r.get('received_date') and start.isoformat()<=r['received_date']<=end.isoformat()),Decimal(0))
    open_rows=[r for r in relevant if r['status']=='open' and r['date']<=end.isoformat()]
    potential=sum((amount(r['amount']) for r in open_rows if r.get('last_activity') and (end-date.fromisoformat(r['last_activity'])).days>=30),Decimal(0))
    eligible=[c for c in (claims or []) if c['status'] in {'approved','invoiced'} and c['data']['currency']==currency and start.isoformat()<=c['data']['received_date']<=end.isoformat()]
    recovered=sum((amount(c['data']['eligible_amount']) for c in eligible),Decimal(0))
    fees=sum((fee(c['data']['eligible_amount']) for c in eligible),Decimal(0))
    return {'recorded_won':str(won.quantize(Decimal('.01'))),'reported_receipts':str(receipts.quantize(Decimal('.01'))),'potential_stalled':str(potential.quantize(Decimal('.01'))),'approved_recovered':str(recovered.quantize(Decimal('.01'))),'approved_fee':str(fees.quantize(Decimal('.01'))),'recovery_percentage':str((recovered/receipts*100).quantize(Decimal('.01'))) if receipts>0 and recovered<=receipts else None,'percentage_basis':'Approved recovered receipts / reported receipts; unavailable if denominator is missing or inconsistent','currency':currency,'start':start.isoformat(),'end':end.isoformat(),'rows':len(rows),'warnings':['CSV receipts are customer-reported, not independently verified.','Potential stalled value is a 30-day inactivity heuristic, not a prediction.','No FX conversion; original currencies remain separate.','Recovery requires separately reviewed evidence; CSV alone never qualifies.']}
def safe_cell(v):
    s=str(v)
    return "'"+s if s.lstrip().startswith(('=','+','-','@','\t','\r')) else s



