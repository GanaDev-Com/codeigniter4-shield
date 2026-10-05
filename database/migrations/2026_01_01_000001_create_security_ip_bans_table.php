<?php

declare(strict_types=1);

use CodeIgniter\Database\Migration;

return new class extends Migration
{
    public function up(): void
    {
        $this->forge->addField([
            'id' => ['type' => 'INT', 'constraint' => 11, 'unsigned' => true, 'auto_increment' => true],
            'ip_address' => ['type' => 'VARCHAR', 'constraint' => 45],
            'status' => ['type' => 'VARCHAR', 'constraint' => 20, 'default' => 'active'],
            'reason' => ['type' => 'VARCHAR', 'constraint' => 255, 'default' => ''],
            'last_rule_id' => ['type' => 'VARCHAR', 'constraint' => 100, 'null' => true],
            'risk_score' => ['type' => 'INT', 'constraint' => 11, 'default' => 0],
            'violation_count' => ['type' => 'INT', 'constraint' => 11, 'default' => 0],
            'offense_count' => ['type' => 'INT', 'constraint' => 11, 'default' => 0],
            'banned_at' => ['type' => 'DATETIME', 'null' => true],
            'expires_at' => ['type' => 'DATETIME', 'null' => true],
            'released_at' => ['type' => 'DATETIME', 'null' => true],
            'challenge_passed_at' => ['type' => 'DATETIME', 'null' => true],
            'last_seen_at' => ['type' => 'DATETIME', 'null' => true],
            'metadata' => ['type' => 'JSON', 'null' => true],
            'created_at' => ['type' => 'DATETIME', 'null' => true],
            'updated_at' => ['type' => 'DATETIME', 'null' => true],
        ]);
        $this->forge->addKey('id', true);
        $this->forge->addKey('ip_address');
        $this->forge->addKey(['status', 'expires_at']);
        $this->forge->createTable('security_ip_bans');
    }

    public function down(): void
    {
        $this->forge->dropTable('security_ip_bans');
    }
};
