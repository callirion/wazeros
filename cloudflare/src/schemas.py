import re
from pydantic import BaseModel, Field, field_validator
class Credentials(BaseModel):
    email: str = Field(max_length=254)
    password: str = Field(min_length=12, max_length=128)
    @field_validator('email')
    @classmethod
    def email_format(cls, value):
        value=value.strip().lower()
        if not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+',value): raise ValueError('Enter a valid email')
        return value
class Signup(Credentials):
    accept_terms: bool
    document_version: str
class EmailRequest(BaseModel):
    email: str = Field(max_length=254)
class TokenRequest(BaseModel):
    token: str = Field(min_length=20, max_length=128)
class ResetRequest(TokenRequest):
    password: str = Field(min_length=12, max_length=128)
class WorkspaceInput(BaseModel):
    name: str = Field(min_length=2,max_length=120)
    industry: str = 'general'
    currency: str = 'USD'
    @field_validator('name')
    @classmethod
    def clean_name(cls,value):
        value=value.strip()
        if len(value)<2: raise ValueError('Workspace name is too short')
        return value
    @field_validator('industry')
    @classmethod
    def industry_valid(cls,value):
        if value not in {'general', 'agency', 'real_estate', 'property_rental', 'dealership', 'professional_services', 'saas', 'clinic', 'education', 'car_rental', 'hospitality'}: raise ValueError('Unsupported industry')
        return value
    @field_validator('currency')
    @classmethod
    def currency_valid(cls,value):
        if value not in {'USD','EUR','GBP','MAD','CAD','AUD','JPY','CHF','AED','SAR'}: raise ValueError('Unsupported currency')
        return value
class InviteInput(BaseModel):
    email: str = Field(max_length=254)
    role: str = 'member'
    @field_validator('email')
    @classmethod
    def email_valid(cls,value): return Credentials.email_format(value)
    @field_validator('role')
    @classmethod
    def role_valid(cls,value):
        if value not in {'admin','manager','member'}: raise ValueError('Unsupported role')
        return value
class RoleInput(BaseModel):
    role: str
    @field_validator('role')
    @classmethod
    def role_valid(cls,value): return InviteInput.role_valid(value)


class PreferencesInput(BaseModel):
    locale: str
    @field_validator('locale')
    @classmethod
    def locale_valid(cls,value):
        if value not in {'en','fr','ar'}: raise ValueError('Unsupported language')
        return value
class CurrencyInput(BaseModel):
    currency: str
    @field_validator('currency')
    @classmethod
    def currency_valid(cls,value): return WorkspaceInput.currency_valid(value)


from decimal import Decimal
from datetime import date
class RevenueInput(BaseModel):
    label: str=Field(min_length=2,max_length=120)
    amount: Decimal=Field(gt=0,le=Decimal('999999999999.99'),max_digits=14,decimal_places=2)
    currency: str
    occurred_on: date
    @field_validator('label')
    @classmethod
    def label_valid(cls,value):
        value=value.strip()
        if len(value)<2: raise ValueError('Label too short')
        return value
    @field_validator('currency')
    @classmethod
    def currency_valid(cls,value): return WorkspaceInput.currency_valid(value)
    @field_validator('occurred_on')
    @classmethod
    def date_valid(cls,value):
        if value>date.today(): raise ValueError('Recorded revenue cannot be in the future')
        return value



