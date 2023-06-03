import unittest
from unittest import IsolatedAsyncioTestCase
from unittest.mock import MagicMock
from fastapi import Request, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime

from database.models import User, Contact
from database.db import get_db
from main import UserModel, create_contact, signup, get_contacts,get_contact, update_contact, delete_contact
from shemas import ContactCreate, ContactUpdate

date_of_birth = datetime.strptime("1990-01-01", "%Y-%m-%d").date()

class TestMain(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.session = MagicMock(spec=Session)
        self.user = User(id=1)
        self.db = get_db

    async def test_create_contact(self):
        contact = ContactCreate(
            first_name="John",
            last_name="Doe",
            email="johndoe@example.com",
            phone_number="1234567890",
            date_of_birth=date_of_birth,
        )
        result = await create_contact(contact=contact, current_user=self.user, db = self.session)
        self.assertEqual(result.first_name, contact.first_name)
        self.assertEqual(result.last_name, contact.last_name)
        self.assertEqual(result.email, contact.email)
        self.assertEqual(result.date_of_birth, contact.date_of_birth)

    async def test_get_contacts(self):
        contacts = [Contact(), Contact(), Contact()]
        self.session.query().filter().all.return_value = contacts
        result = await get_contacts(current_user=self.user, db = self.session)
        self.assertEqual(result, {"contacts": contacts})

    async def test_get_contact_found(self):
        contact = Contact()
        self.session.query().filter().first.return_value = contact
        result = await get_contact(contact_id=1, current_user=self.user, db = self.session)
        self.assertEqual(result, contact)

    async def test_get_contact_not_found(self):
        self.session.query().filter().first.return_value = None
        with self.assertRaises(HTTPException) as cm:
            await get_contact(contact_id=1, current_user=self.user, db=self.session)
        self.assertEqual(cm.exception.status_code, 404)
        self.assertEqual(cm.exception.detail, "Contact not found")

    async def test_update_contact_found(self):
        contact_id = 1
        updated_data = ContactUpdate(
            first_name="John",
            last_name="Doe",
            email="johndoe@example.com",
            phone_number="1234567890",
            date_of_birth="1990-01-01",
        )
        existing_contact = Contact(id=contact_id, user_id=self.user.id)
        self.session.query().filter().first.return_value = existing_contact

        result = await update_contact(contact_id=contact_id, contact=updated_data, current_user=self.user, db=self.session)

        self.assertEqual(result.id, contact_id)
        self.assertEqual(result.first_name, updated_data.first_name)
        self.assertEqual(result.last_name, updated_data.last_name)
        self.assertEqual(result.email, updated_data.email)
        self.assertEqual(result.phone_number, updated_data.phone_number)
        self.assertEqual(result.date_of_birth, updated_data.date_of_birth)

    async def test_update_contact_not_found(self):
        contact_id = 1
        updated_data = ContactUpdate(
            first_name="John",
            last_name="Doe",
            email="johndoe@example.com",
            phone_number="1234567890",
            date_of_birth="1990-01-01",
        )
        self.session.query().filter().first.return_value = None

        with self.assertRaises(HTTPException) as cm:
            await update_contact(contact_id=contact_id, contact=updated_data, current_user=self.user, db=self.session)

        self.assertEqual(cm.exception.status_code, 404)
        self.assertEqual(cm.exception.detail, "Contact not found")

    async def test_delete_contact_found(self):
        contact_id = 1
        existing_contact = Contact(id=contact_id, user_id=self.user.id)
        self.session.query().filter().first.return_value = existing_contact

        result = await delete_contact(contact_id=contact_id, current_user=self.user, db=self.session)

        self.assertEqual(result, {"message": "Contact deleted successfully"})

    async def test_delete_contact_not_found(self):
        contact_id = 1
        self.session.query().filter().first.return_value = None

        with self.assertRaises(HTTPException) as cm:
            await delete_contact(contact_id=contact_id, current_user=self.user, db=self.session)

        self.assertEqual(cm.exception.status_code, 404)
        self.assertEqual(cm.exception.detail, "Contact not found")


if __name__ == '__main__':
    unittest.main()
