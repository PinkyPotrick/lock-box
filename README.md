# LockBox
An advanced password manager developed for my Cybersecurity Masters Dissertation.

Key features of the password manager:

- Password Generation and Storage
- Multi-factor authentication (*with geolocation tracking of the used password)
- Security Dashboard (security health reports)
- Zero-knowledge architecture (SRP protocol + E2EE + fully encrypted database)
- Zero-trust achitecture
- Blockchain integration
- Audit Logging

- *Secure Notes and File Storage
- *Emergency Access
- *Password Sharing
- *Travel Mode

Other quality of life features:

- Customizable Vaults
- Notifications System

- *Browser Extensions
- *Secure Autofill
- *Offline Access
- *AI-Powered Password Suggestions 
- *Voice Authentication
- *Secure Messaging
- *Blockchain-Based Security with De-centralized Storage
- *Role-Based Access Control
- *Audit Logs

*Features that would be nice to have.

## Database Schema Management

Enum constraints for database tables are automatically generated during the build process.
To apply these constraints to your development database:

1. Run `mvn compile` to generate the latest constraints
2. Apply the generated SQL from `/sql/update_enum_constraints.sql` to your database
