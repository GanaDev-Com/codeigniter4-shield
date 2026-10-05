<?php

declare(strict_types=1);

namespace Ganadev\Shield\Codeigniter\Database\Migrations;

use CodeIgniter\Database\Migration;

class CreateSecurityEvents extends Migration
{
    public function up(): void
    {
        $this->forge->addField([
            'id' => [
                'type' => 'INT',
                'constraint' => 11,
                'unsigned' => true,
                'auto_increment' => true,
            ],
            'ip_address' => [
                'type' => 'VARCHAR',
                'constraint' => 45,
            ],
            'host' => [
                'type' => 'VARCHAR',
                'constraint' => 255,
            ],
            'method' => [
                'type' => 'VARCHAR',
                'constraint' => 10,
                'default' => 'GET',
            ],
            'raw_uri' => [
                'type' => 'TEXT',
                'null' => true,
            ],
            'normalized_uri' => [
                'type' => 'TEXT',
                'null' => true,
            ],
            'rule_id' => [
                'type' => 'VARCHAR',
                'constraint' => 100,
                'null' => true,
            ],
            'category' => [
                'type' => 'VARCHAR',
                'constraint' => 100,
                'null' => true,
            ],
            'severity' => [
                'type' => 'VARCHAR',
                'constraint' => 20,
                'default' => 'low',
            ],
            'score_delta' => [
                'type' => 'INT',
                'constraint' => 11,
                'default' => 0,
            ],
            'decision' => [
                'type' => 'VARCHAR',
                'constraint' => 30,
                'default' => 'ALLOW',
            ],
            'intended_decision' => [
                'type' => 'VARCHAR',
                'constraint' => 30,
                'null' => true,
            ],
            'user_agent' => [
                'type' => 'TEXT',
                'null' => true,
            ],
            'referer' => [
                'type' => 'TEXT',
                'null' => true,
            ],
            'request_id' => [
                'type' => 'VARCHAR',
                'constraint' => 100,
                'null' => true,
            ],
            'rule_version' => [
                'type' => 'VARCHAR',
                'constraint' => 50,
                'null' => true,
            ],
            'created_at' => [
                'type' => 'DATETIME',
                'null' => true,
            ],
        ]);

        $this->forge->addKey('id', true);
        $this->forge->addKey('ip_address');
        $this->forge->addKey('host');
        $this->forge->addKey('rule_id');
        $this->forge->addKey('created_at');
        $this->forge->addKey(['ip_address', 'created_at']);
        $this->forge->createTable('security_events');
    }

    public function down(): void
    {
        $this->forge->dropTable('security_events');
    }
}
