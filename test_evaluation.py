import unittest
import pandas as pd
from app import app
from bfs_engine import build_infrastructure_graph, custom_bfs, custom_dfs, reconstruct_path


class TestCyberTraceFullSystem(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.df_emp = pd.read_csv("data/employees.csv")
        cls.df_dev = pd.read_csv("data/devices.csv")
        cls.df_logs = pd.read_csv("data/login_logs.csv")
        cls.client = app.test_client()

    def test_01_all_five_pages_load_200(self):
        """Verify all 5 separate web pages render HTTP 200 without template errors."""
        for route in ["/", "/graph", "/bfs", "/results", "/report"]:
            res = self.client.get(route)
            self.assertEqual(res.status_code, 200, f"Route {route} failed to load.")

    def test_02_overview_api_metrics(self):
        """Verify /api/overview returns exact counts for 100 users and 150 devices."""
        res = self.client.get("/api/overview?exclude_gateway=true")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["metrics"]["total_users"], 100)
        self.assertEqual(data["metrics"]["connected_devices"], 150)
        self.assertGreater(data["metrics"]["recent_events_count"], 0)

    def test_03_investigate_api_shortest_path(self):
        """Verify /api/investigate computes the exact 7-hop attack chain from U001 to D150."""
        res = self.client.post("/api/investigate", json={
            "start_node": "U001",
            "target_node": "D150",
            "max_depth": 8,
            "exclude_gateway": True
        })
        self.assertEqual(res.status_code, 200)
        data = res.get_json()

        expected_path = [
            "U001", "D101", "10.24.4.12", "D004",
            "10.24.7.88", "D145", "10.24.1.5", "D150"
        ]
        self.assertEqual(data["shortest_chain"], expected_path)
        self.assertEqual(data["discovered"][0]["classification"], "Confirmed Compromised")
        self.assertEqual(data["discovered"][1]["classification"], "Potentially Exposed")

    def test_04_shared_gateway_noise_filter(self):
        """Verify suppressing shared Wi-Fi IP reduces false-positive blast radius."""
        gateway_user = self.df_logs[self.df_logs["is_shared_gateway"] == True]["user_id"].iloc[0]

        _, adj_clean, _, _, _ = build_infrastructure_graph(
            self.df_emp, self.df_dev, self.df_logs, exclude_shared_gateway=True
        )
        _, adj_noisy, _, _, _ = build_infrastructure_graph(
            self.df_emp, self.df_dev, self.df_logs, exclude_shared_gateway=False
        )

        bfs_clean = custom_bfs(adj_clean, gateway_user, max_depth=3)
        bfs_noisy = custom_bfs(adj_noisy, gateway_user, max_depth=3)
        self.assertLess(len(bfs_clean["visited"]), len(bfs_noisy["visited"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)