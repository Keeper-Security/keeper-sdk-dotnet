using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Common;
using KeeperSecurity.Storage;

namespace KeeperSecurity.Compliance
{
    /// <exclude />
    public class SqlComplianceStorage
    {
        private readonly SqlRecordStorage<ComplianceMetadata, ComplianceMetadata> _metadata;
        private readonly SqlEntityStorage<IComplianceUser, ComplianceUser> _users;
        private readonly SqlEntityStorage<IComplianceRecord, ComplianceRecord> _records;
        private readonly SqlEntityStorage<IComplianceRecordAging, ComplianceRecordAging> _recordAging;
        private readonly SqlEntityStorage<IComplianceTeam, ComplianceTeam> _teams;
        private readonly SqlEntityStorage<IComplianceRole, ComplianceRole> _roles;
        private readonly SqlLinkStorage<IComplianceUserRecordLink, ComplianceUserRecordLink> _userRecordLinks;
        private readonly SqlLinkStorage<IComplianceTeamUserLink, ComplianceTeamUserLink> _teamUserLinks;
        private readonly SqlLinkStorage<IComplianceRecordPermissions, ComplianceRecordPermissions> _recordPermissions;
        private readonly SqlLinkStorage<IComplianceSfRecordLink, ComplianceSfRecordLink> _sfRecordLinks;
        private readonly SqlLinkStorage<IComplianceSfUserLink, ComplianceSfUserLink> _sfUserLinks;
        private readonly SqlLinkStorage<IComplianceSfTeamLink, ComplianceSfTeamLink> _sfTeamLinks;

        public SqlComplianceStorage(Func<IDbConnection> getConnection, ISqlDialect dialect)
        {
            _metadata = new SqlRecordStorage<ComplianceMetadata, ComplianceMetadata>(getConnection, dialect);
            _users = new SqlEntityStorage<IComplianceUser, ComplianceUser>(getConnection, dialect);
            _records = new SqlEntityStorage<IComplianceRecord, ComplianceRecord>(getConnection, dialect);
            _recordAging = new SqlEntityStorage<IComplianceRecordAging, ComplianceRecordAging>(getConnection, dialect);
            _teams = new SqlEntityStorage<IComplianceTeam, ComplianceTeam>(getConnection, dialect);
            _roles = new SqlEntityStorage<IComplianceRole, ComplianceRole>(getConnection, dialect);
            _userRecordLinks = new SqlLinkStorage<IComplianceUserRecordLink, ComplianceUserRecordLink>(getConnection, dialect);
            _teamUserLinks = new SqlLinkStorage<IComplianceTeamUserLink, ComplianceTeamUserLink>(getConnection, dialect);
            _recordPermissions = new SqlLinkStorage<IComplianceRecordPermissions, ComplianceRecordPermissions>(getConnection, dialect);
            _sfRecordLinks = new SqlLinkStorage<IComplianceSfRecordLink, ComplianceSfRecordLink>(getConnection, dialect);
            _sfUserLinks = new SqlLinkStorage<IComplianceSfUserLink, ComplianceSfUserLink>(getConnection, dialect);
            _sfTeamLinks = new SqlLinkStorage<IComplianceSfTeamLink, ComplianceSfTeamLink>(getConnection, dialect);
        }

        public IEnumerable<SqlStorage> GetStorages()
        {
            yield return _metadata;
            yield return _users;
            yield return _records;
            yield return _recordAging;
            yield return _teams;
            yield return _roles;
            yield return _userRecordLinks;
            yield return _teamUserLinks;
            yield return _recordPermissions;
            yield return _sfRecordLinks;
            yield return _sfUserLinks;
            yield return _sfTeamLinks;
        }

        public IRecordStorage<ComplianceMetadata> Metadata => _metadata;
        public IEntityStorage<IComplianceUser> Users => _users;
        public IEntityStorage<IComplianceRecord> Records => _records;
        public IEntityStorage<IComplianceRecordAging> RecordAging => _recordAging;
        public IEntityStorage<IComplianceTeam> Teams => _teams;
        public IEntityStorage<IComplianceRole> Roles => _roles;
        public ILinkStorage<IComplianceUserRecordLink> UserRecordLinks => _userRecordLinks;
        public ILinkStorage<IComplianceTeamUserLink> TeamUserLinks => _teamUserLinks;
        public ILinkStorage<IComplianceRecordPermissions> RecordPermissions => _recordPermissions;
        public ILinkStorage<IComplianceSfRecordLink> SfRecordLinks => _sfRecordLinks;
        public ILinkStorage<IComplianceSfUserLink> SfUserLinks => _sfUserLinks;
        public ILinkStorage<IComplianceSfTeamLink> SfTeamLinks => _sfTeamLinks;

        /// <summary>
        /// Clears snapshot data (users, records, teams, roles, links) without touching aging rows.
        /// Resets prelim/compliance timestamps in metadata but preserves aging timestamps.
        /// </summary>
        public void ClearNonAgingData()
        {
            _records.DeleteAll();
            _users.DeleteAll();
            _userRecordLinks.DeleteAll();
            _teams.DeleteAll();
            _roles.DeleteAll();
            _sfTeamLinks.DeleteAll();
            _sfUserLinks.DeleteAll();
            _sfRecordLinks.DeleteAll();
            _teamUserLinks.DeleteAll();
            _recordPermissions.DeleteAll();
        }

        /// <summary>Clears only aging rows.</summary>
        public void ClearAgingData()
        {
            _recordAging.DeleteAll();
        }

        /// <summary>Clears all tables including metadata, snapshot, and aging data.</summary>
        public void Clear()
        {
            ClearNonAgingData();
            _recordAging.DeleteAll();
            _metadata.DeleteAll();
        }

        public static void VerifyDatabase(DbConnection connection, ISqlDialect dialect)
        {
            var schemas = new[]
            {
                new TableSchema(typeof(ComplianceMetadata)),
                new TableSchema(typeof(ComplianceUser)),
                new TableSchema(typeof(ComplianceRecord)),
                new TableSchema(typeof(ComplianceRecordAging)),
                new TableSchema(typeof(ComplianceTeam)),
                new TableSchema(typeof(ComplianceRole)),
                new TableSchema(typeof(ComplianceUserRecordLink)),
                new TableSchema(typeof(ComplianceTeamUserLink)),
                new TableSchema(typeof(ComplianceRecordPermissions)),
                new TableSchema(typeof(ComplianceSfRecordLink)),
                new TableSchema(typeof(ComplianceSfUserLink)),
                new TableSchema(typeof(ComplianceSfTeamLink)),
            };
            DatabaseUtils.VerifyDatabase(connection, dialect, schemas);
        }
    }
}
