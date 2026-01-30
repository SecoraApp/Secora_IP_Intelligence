# Initialize database
def init_db():
    """Initialize the database with proper schema migration"""
    with app.app_context():
        try:
            # Check if we need to migrate from OAuth to password schema
            inspector = db.inspect(db.engine)
            if inspector.has_table('user'):
                columns = [col['name'] for col in inspector.get_columns('user')]

                # If old OAuth schema detected, drop all tables and recreate
                if 'oauth_provider' in columns and 'password_hash' not in columns:
                    print("🔄 Migrating from OAuth to password authentication...")
                    db.drop_all()
                    db.create_all()
                    print("✅ Database migrated successfully!")
                elif 'password_hash' not in columns:
                    # Missing password_hash column, recreate tables
                    print("🔄 Fixing database schema...")
                    db.drop_all()
                    db.create_all()
                    print("✅ Database schema fixed!")
                else:
                    # Schema looks correct, just ensure all tables exist
                    db.create_all()
                    print("✅ Database schema verified!")
            else:
                # No tables exist, create them
                db.create_all()
                print("✅ Database initialized successfully!")

        except Exception as e:
            print(f"❌ Database initialization error: {e}")
            # Force recreation on any error
            try:
                db.drop_all()
                db.create_all()
                print("✅ Database forcefully recreated!")
            except Exception as e2:
                print(f"❌ Failed to recreate database: {e2}")
                print("💡 Please manually delete the instance/ip_lookup.db file and restart.")


