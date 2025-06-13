package com.example.courseworkLuchnetskyi;

import com.example.courseworkLuchnetskyi.dto.request.*;
import com.example.courseworkLuchnetskyi.dto.response.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import org.springframework.transaction.annotation.Transactional;

@SpringBootTest
@AutoConfigureMockMvc
@Transactional
public class SecurityIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    private String jwtToken;

    @BeforeEach
    public void setup() throws Exception {
        // Register a user, ignore if already exists
        var registerResult = mockMvc.perform(post("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"testuser\",\"password\":\"testpass\"}"))
                .andReturn();

        int status = registerResult.getResponse().getStatus();
        if (status != 200 && status != 400) { // 400 means user exists, ignore
            throw new RuntimeException("Unexpected status during registration: " + status);
        }

        // Login and get JWT token from cookie
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"testuser\",\"password\":\"testpassword\"}"))
                .andExpect(status().isOk())
                .andReturn();

        String setCookie = result.getResponse().getHeader("Set-Cookie");
        assertThat(setCookie).isNotNull();
        // Extract JWT_TOKEN cookie value
        String token = null;
        for (String cookie : setCookie.split(";")) {
            if (cookie.trim().startsWith("JWT_TOKEN=")) {
                token = cookie.trim().substring("JWT_TOKEN=".length());
                break;
            }
        }
        jwtToken = token;
        assertThat(jwtToken).isNotNull();
    }

    private String authHeader() {
        return "Bearer " + jwtToken;
    }

    // Helper method to perform unauthorized request and expect 401
    private void expectUnauthorized(String url, String method) throws Exception {
        switch (method) {
            case "POST":
                mockMvc.perform(post(url)).andExpect(status().isUnauthorized());
                break;
            case "GET":
                mockMvc.perform(get(url)).andExpect(status().isUnauthorized());
                break;
            case "PUT":
                mockMvc.perform(put(url)).andExpect(status().isUnauthorized());
                break;
            case "DELETE":
                mockMvc.perform(delete(url)).andExpect(status().isUnauthorized());
                break;
        }
    }

    // Test 1: Add tournament (unauthenticated should fail)
    @Test
    public void testAddTournament_Unauthenticated_Fails() throws Exception {
        expectUnauthorized("/api/tournaments", "POST");
    }

    // Test 1: Add tournament (authenticated should succeed)
    @Test
    public void testAddTournament_Authenticated_Succeeds() throws Exception {
        TournamentRequestDto dto = new TournamentRequestDto("Test Tournament", java.time.LocalDate.of(2024, 1, 1), java.time.LocalDate.of(2024, 1, 10), "Description");
        mockMvc.perform(post("/api/tournaments")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(dto))
                .cookie(new jakarta.servlet.http.Cookie("JWT_TOKEN", jwtToken)))
                .andExpect(status().isCreated());
    }

    // Test 2: Get all tournaments
    @Test
    public void testGetAllTournaments_Unauthenticated_Fails() throws Exception {
        expectUnauthorized("/api/tournaments", "GET");
    }

    @Test
    public void testGetAllTournaments_Authenticated_Succeeds() throws Exception {
        mockMvc.perform(get("/api/tournaments")
                .cookie(new jakarta.servlet.http.Cookie("JWT_TOKEN", jwtToken)))
                .andExpect(status().isOk());
    }

    // Test 3: Update tournament
    @Test
    public void testUpdateTournament_Unauthenticated_Fails() throws Exception {
        expectUnauthorized("/api/tournaments/1", "PUT");
    }

    @Test
    public void testUpdateTournament_Authenticated_Succeeds() throws Exception {
        // Create tournament first
        TournamentRequestDto createDto = new TournamentRequestDto("To Update", java.time.LocalDate.of(2024, 1, 1), java.time.LocalDate.of(2024, 1, 5), "Temp");
        MvcResult result = mockMvc.perform(post("/api/tournaments")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(createDto))
                .cookie(new jakarta.servlet.http.Cookie("JWT_TOKEN", jwtToken)))
                .andExpect(status().isCreated())
                .andReturn();

        String content = result.getResponse().getContentAsString();
        com.example.courseworkLuchnetskyi.dto.response.TournamentResponseDto created = objectMapper.readValue(content, com.example.courseworkLuchnetskyi.dto.response.TournamentResponseDto.class);
        Long id = created.id();

        // Update tournament
        TournamentRequestDto updateDto = new TournamentRequestDto("Updated Tournament", java.time.LocalDate.of(2024, 1, 1), java.time.LocalDate.of(2024, 1, 10), "Updated Description");
        mockMvc.perform(put("/api/tournaments/" + id)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(updateDto))
                .cookie(new jakarta.servlet.http.Cookie("JWT_TOKEN", jwtToken)))
                .andExpect(status().isOk());
    }

    // Test 4: Delete tournament
    @Test
    public void testDeleteTournament_Unauthenticated_Fails() throws Exception {
        expectUnauthorized("/api/tournaments/1", "DELETE");
    }

    @Test
    public void testDeleteTournament_Authenticated_Succeeds() throws Exception {
        // Create tournament first
        TournamentRequestDto createDto = new TournamentRequestDto("To Delete", java.time.LocalDate.of(2024, 1, 1), java.time.LocalDate.of(2024, 1, 5), "Temp");
        MvcResult result = mockMvc.perform(post("/api/tournaments")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(createDto))
                .cookie(new jakarta.servlet.http.Cookie("JWT_TOKEN", jwtToken)))
                .andExpect(status().isCreated())
                .andReturn();

        String content = result.getResponse().getContentAsString();
        com.example.courseworkLuchnetskyi.dto.response.TournamentResponseDto created = objectMapper.readValue(content, com.example.courseworkLuchnetskyi.dto.response.TournamentResponseDto.class);
        Long id = created.id();

        // Delete tournament
        mockMvc.perform(delete("/api/tournaments/" + id)
                .cookie(new jakarta.servlet.http.Cookie("JWT_TOKEN", jwtToken)))
                .andExpect(status().isNoContent());
    }

    // Test 5: Add team
    @Test
    public void testAddTeam_Unauthenticated_Fails() throws Exception {
        expectUnauthorized("/api/teams", "POST");
    }

    @Test
    public void testAddTeam_Authenticated_Succeeds() throws Exception {
        // Assuming TeamRequestDto has a constructor with name and description
        var dto = new com.example.courseworkLuchnetskyi.dto.request.TeamRequestDto("Team A", "Description");
        mockMvc.perform(post("/api/teams")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(dto))
                .cookie(new jakarta.servlet.http.Cookie("JWT_TOKEN", jwtToken)))
                .andExpect(status().isOk());
    }

    // Test 6: Get all teams
    @Test
    public void testGetAllTeams_Unauthenticated_Fails() throws Exception {
        expectUnauthorized("/api/teams", "GET");
    }

    @Test
    public void testGetAllTeams_Authenticated_Succeeds() throws Exception {
        mockMvc.perform(get("/api/teams")
                .cookie(new jakarta.servlet.http.Cookie("JWT_TOKEN", jwtToken)))
                .andExpect(status().isOk());
    }

    // Test 7: Update team
    @Test
    public void testUpdateTeam_Unauthenticated_Fails() throws Exception {
        expectUnauthorized("/api/teams/1", "PUT");
    }

    @Test
    public void testUpdateTeam_Authenticated_Succeeds() throws Exception {
        // Create team first
        var createDto = new com.example.courseworkLuchnetskyi.dto.request.TeamRequestDto("To Update", "Temp");
        MvcResult result = mockMvc.perform(post("/api/teams")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(createDto))
                .cookie(new jakarta.servlet.http.Cookie("JWT_TOKEN", jwtToken)))
                .andExpect(status().isOk())
                .andReturn();

        String content = result.getResponse().getContentAsString();
        com.example.courseworkLuchnetskyi.dto.response.TeamResponseDto created = objectMapper.readValue(content, com.example.courseworkLuchnetskyi.dto.response.TeamResponseDto.class);
        Long id = created.id();

        // Update team
        var updateDto = new com.example.courseworkLuchnetskyi.dto.request.TeamRequestDto("Updated Team", "Updated Description");
        mockMvc.perform(put("/api/teams/" + id)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(updateDto))
                .cookie(new jakarta.servlet.http.Cookie("JWT_TOKEN", jwtToken)))
                .andExpect(status().isOk());
    }

    // Test 8: Delete team
    @Test
    public void testDeleteTeam_Unauthenticated_Fails() throws Exception {
        expectUnauthorized("/api/teams/1", "DELETE");
    }

    @Test
    public void testDeleteTeam_Authenticated_Succeeds() throws Exception {
        // Create team first
        var createDto = new com.example.courseworkLuchnetskyi.dto.request.TeamRequestDto("To Delete", "Temp");
        MvcResult result = mockMvc.perform(post("/api/teams")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(createDto))
                .cookie(new jakarta.servlet.http.Cookie("JWT_TOKEN", jwtToken)))
                .andExpect(status().isOk())
                .andReturn();

        String content = result.getResponse().getContentAsString();
        com.example.courseworkLuchnetskyi.dto.response.TeamResponseDto created = objectMapper.readValue(content, com.example.courseworkLuchnetskyi.dto.response.TeamResponseDto.class);
        Long id = created.id();

        // Delete team
        mockMvc.perform(delete("/api/teams/" + id)
                .cookie(new jakarta.servlet.http.Cookie("JWT_TOKEN", jwtToken)))
                .andExpect(status().isNoContent());
    }

    // Test 9: Add player
    @Test
    public void testAddPlayer_Unauthenticated_Fails() throws Exception {
        expectUnauthorized("/api/players", "POST");
    }

    @Test
    public void testAddPlayer_Authenticated_Succeeds() throws Exception {
        var dto = new com.example.courseworkLuchnetskyi.dto.request.PlayerRequestDto("Player1", java.time.LocalDate.of(2000, 1, 1), "Position", 1L);
        mockMvc.perform(post("/api/players")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(dto))
                .cookie(new jakarta.servlet.http.Cookie("JWT_TOKEN", jwtToken)))
                .andExpect(status().isCreated());
    }

    // Test 10: Get players of a team
    @Test
    public void testGetPlayersByTeam_Unauthenticated_Fails() throws Exception {
        expectUnauthorized("/api/players/team/1", "GET");
    }

    @Test
    public void testGetPlayersByTeam_Authenticated_Succeeds() throws Exception {
        mockMvc.perform(get("/api/players/team/1")
                .cookie(new jakarta.servlet.http.Cookie("JWT_TOKEN", jwtToken)))
                .andExpect(status().isOk());
    }

    // Test 11: Update player
    @Test
    public void testUpdatePlayer_Unauthenticated_Fails() throws Exception {
        expectUnauthorized("/api/players/1", "PUT");
    }

    @Test
    public void testUpdatePlayer_Authenticated_Succeeds() throws Exception {
        // Create team first (dependency)
        var teamDto = new com.example.courseworkLuchnetskyi.dto.request.TeamRequestDto("Team for Player", "Temp");
        MvcResult teamResult = mockMvc.perform(post("/api/teams")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(teamDto))
                .cookie(new jakarta.servlet.http.Cookie("JWT_TOKEN", jwtToken)))
                .andExpect(status().isOk())
                .andReturn();

        String teamContent = teamResult.getResponse().getContentAsString();
        com.example.courseworkLuchnetskyi.dto.response.TeamResponseDto createdTeam = objectMapper.readValue(teamContent, com.example.courseworkLuchnetskyi.dto.response.TeamResponseDto.class);
        Long teamId = createdTeam.id();

        // Create player first
        var createDto = new com.example.courseworkLuchnetskyi.dto.request.PlayerRequestDto("Player1", java.time.LocalDate.of(2000, 1, 1), "Position", teamId);
        MvcResult playerResult = mockMvc.perform(post("/api/players")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(createDto))
                .cookie(new jakarta.servlet.http.Cookie("JWT_TOKEN", jwtToken)))
                .andExpect(status().isCreated())
                .andReturn();

        String playerContent = playerResult.getResponse().getContentAsString();
        com.example.courseworkLuchnetskyi.dto.response.PlayerResponseDto createdPlayer = objectMapper.readValue(playerContent, com.example.courseworkLuchnetskyi.dto.response.PlayerResponseDto.class);
        Long playerId = createdPlayer.id();

        // Update player
        var updateDto = new com.example.courseworkLuchnetskyi.dto.request.PlayerRequestDto("Updated Player", java.time.LocalDate.of(2000, 1, 1), "Updated Position", teamId);
        mockMvc.perform(put("/api/players/" + playerId)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(updateDto))
                .cookie(new jakarta.servlet.http.Cookie("JWT_TOKEN", jwtToken)))
                .andExpect(status().isOk());
    }

    // Test 12: Delete player
    @Test
    public void testDeletePlayer_Unauthenticated_Fails() throws Exception {
        expectUnauthorized("/api/players/1", "DELETE");
    }

    @Test
    public void testDeletePlayer_Authenticated_Succeeds() throws Exception {
        // Create team first (dependency)
        var teamDto = new com.example.courseworkLuchnetskyi.dto.request.TeamRequestDto("Team for Player", "Temp");
        MvcResult teamResult = mockMvc.perform(post("/api/teams")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(teamDto))
                .cookie(new jakarta.servlet.http.Cookie("JWT_TOKEN", jwtToken)))
                .andExpect(status().isOk())
                .andReturn();

        String teamContent = teamResult.getResponse().getContentAsString();
        com.example.courseworkLuchnetskyi.dto.response.TeamResponseDto createdTeam = objectMapper.readValue(teamContent, com.example.courseworkLuchnetskyi.dto.response.TeamResponseDto.class);
        Long teamId = createdTeam.id();

        // Create player first
        var createDto = new com.example.courseworkLuchnetskyi.dto.request.PlayerRequestDto("Player1", java.time.LocalDate.of(2000, 1, 1), "Position", teamId);
        MvcResult playerResult = mockMvc.perform(post("/api/players")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(createDto))
                .cookie(new jakarta.servlet.http.Cookie("JWT_TOKEN", jwtToken)))
                .andExpect(status().isCreated())
                .andReturn();

        String playerContent = playerResult.getResponse().getContentAsString();
        com.example.courseworkLuchnetskyi.dto.response.PlayerResponseDto createdPlayer = objectMapper.readValue(playerContent, com.example.courseworkLuchnetskyi.dto.response.PlayerResponseDto.class);
        Long playerId = createdPlayer.id();

        // Delete player
        mockMvc.perform(delete("/api/players/" + playerId)
                .cookie(new jakarta.servlet.http.Cookie("JWT_TOKEN", jwtToken)))
                .andExpect(status().isNoContent());
    }

    // Test 13: Add match
    @Test
    public void testAddMatch_Unauthenticated_Fails() throws Exception {
        expectUnauthorized("/api/matches", "POST");
    }

    @Test
    public void testAddMatch_Authenticated_Succeeds() throws Exception {
        // Create tournament first
        TournamentRequestDto tournamentDto = new TournamentRequestDto("Tournament for Match", java.time.LocalDate.of(2024, 1, 1), java.time.LocalDate.of(2024, 1, 10), "Desc");
        MvcResult tournamentResult = mockMvc.perform(post("/api/tournaments")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(tournamentDto))
                .cookie(new jakarta.servlet.http.Cookie("JWT_TOKEN", jwtToken)))
                .andExpect(status().isCreated())
                .andReturn();

        String tournamentContent = tournamentResult.getResponse().getContentAsString();
        com.example.courseworkLuchnetskyi.dto.response.TournamentResponseDto createdTournament = objectMapper.readValue(tournamentContent, com.example.courseworkLuchnetskyi.dto.response.TournamentResponseDto.class);
        Long tournamentId = createdTournament.id();

        // Create teams
        var teamDto1 = new com.example.courseworkLuchnetskyi.dto.request.TeamRequestDto("Team 1", "Desc");
        MvcResult teamResult1 = mockMvc.perform(post("/api/teams")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(teamDto1))
                .cookie(new jakarta.servlet.http.Cookie("JWT_TOKEN", jwtToken)))
                .andExpect(status().isOk())
                .andReturn();
        String teamContent1 = teamResult1.getResponse().getContentAsString();
        com.example.courseworkLuchnetskyi.dto.response.TeamResponseDto createdTeam1 = objectMapper.readValue(teamContent1, com.example.courseworkLuchnetskyi.dto.response.TeamResponseDto.class);
        Long teamId1 = createdTeam1.id();

        var teamDto2 = new com.example.courseworkLuchnetskyi.dto.request.TeamRequestDto("Team 2", "Desc");
        MvcResult teamResult2 = mockMvc.perform(post("/api/teams")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(teamDto2))
                .cookie(new jakarta.servlet.http.Cookie("JWT_TOKEN", jwtToken)))
                .andExpect(status().isOk())
                .andReturn();
        String teamContent2 = teamResult2.getResponse().getContentAsString();
        com.example.courseworkLuchnetskyi.dto.response.TeamResponseDto createdTeam2 = objectMapper.readValue(teamContent2, com.example.courseworkLuchnetskyi.dto.response.TeamResponseDto.class);
        Long teamId2 = createdTeam2.id();

        // Create match
        var dto = new com.example.courseworkLuchnetskyi.dto.request.MatchRequestDto(tournamentId, teamId1, teamId2, java.time.LocalDate.of(2024, 1, 1), 0, 0);
        mockMvc.perform(post("/api/matches")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(dto))
                .cookie(new jakarta.servlet.http.Cookie("JWT_TOKEN", jwtToken)))
                .andExpect(status().isCreated());
    }

    // Test 14: Get matches of a tournament
    @Test
    public void testGetMatchesByTournament_Unauthenticated_Fails() throws Exception {
        expectUnauthorized("/api/matches/tournament/1", "GET");
    }

    @Test
    public void testGetMatchesByTournament_Authenticated_Succeeds() throws Exception {
        // Create tournament first
        TournamentRequestDto tournamentDto = new TournamentRequestDto("Tournament for Match", java.time.LocalDate.of(2024, 1, 1), java.time.LocalDate.of(2024, 1, 10), "Desc");
        MvcResult tournamentResult = mockMvc.perform(post("/api/tournaments")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(tournamentDto))
                .cookie(new jakarta.servlet.http.Cookie("JWT_TOKEN", jwtToken)))
                .andExpect(status().isCreated())
                .andReturn();

        String tournamentContent = tournamentResult.getResponse().getContentAsString();
        com.example.courseworkLuchnetskyi.dto.response.TournamentResponseDto createdTournament = objectMapper.readValue(tournamentContent, com.example.courseworkLuchnetskyi.dto.response.TournamentResponseDto.class);
        Long tournamentId = createdTournament.id();

        mockMvc.perform(get("/api/matches/tournament/" + tournamentId)
                .cookie(new jakarta.servlet.http.Cookie("JWT_TOKEN", jwtToken)))
                .andExpect(status().isOk());
    }

    // Test 15: Update match
    @Test
    public void testUpdateMatch_Unauthenticated_Fails() throws Exception {
        expectUnauthorized("/api/matches/1", "PUT");
    }

    @Test
    public void testUpdateMatch_Authenticated_Succeeds() throws Exception {
        // Create tournament first
        TournamentRequestDto tournamentDto = new TournamentRequestDto("Tournament for Match", java.time.LocalDate.of(2024, 1, 1), java.time.LocalDate.of(2024, 1, 10), "Desc");
        MvcResult tournamentResult = mockMvc.perform(post("/api/tournaments")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(tournamentDto))
                .cookie(new jakarta.servlet.http.Cookie("JWT_TOKEN", jwtToken)))
                .andExpect(status().isCreated())
                .andReturn();

        String tournamentContent = tournamentResult.getResponse().getContentAsString();
        com.example.courseworkLuchnetskyi.dto.response.TournamentResponseDto createdTournament = objectMapper.readValue(tournamentContent, com.example.courseworkLuchnetskyi.dto.response.TournamentResponseDto.class);
        Long tournamentId = createdTournament.id();

        // Create teams
        var teamDto1 = new com.example.courseworkLuchnetskyi.dto.request.TeamRequestDto("Team 1", "Desc");
        MvcResult teamResult1 = mockMvc.perform(post("/api/teams")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(teamDto1))
                .cookie(new jakarta.servlet.http.Cookie("JWT_TOKEN", jwtToken)))
                .andExpect(status().isOk())
                .andReturn();
        String teamContent1 = teamResult1.getResponse().getContentAsString();
        com.example.courseworkLuchnetskyi.dto.response.TeamResponseDto createdTeam1 = objectMapper.readValue(teamContent1, com.example.courseworkLuchnetskyi.dto.response.TeamResponseDto.class);
        Long teamId1 = createdTeam1.id();

        var teamDto2 = new com.example.courseworkLuchnetskyi.dto.request.TeamRequestDto("Team 2", "Desc");
        MvcResult teamResult2 = mockMvc.perform(post("/api/teams")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(teamDto2))
                .cookie(new jakarta.servlet.http.Cookie("JWT_TOKEN", jwtToken)))
                .andExpect(status().isOk())
                .andReturn();
        String teamContent2 = teamResult2.getResponse().getContentAsString();
        com.example.courseworkLuchnetskyi.dto.response.TeamResponseDto createdTeam2 = objectMapper.readValue(teamContent2, com.example.courseworkLuchnetskyi.dto.response.TeamResponseDto.class);
        Long teamId2 = createdTeam2.id();

        // Create match
        var createDto = new com.example.courseworkLuchnetskyi.dto.request.MatchRequestDto(tournamentId, teamId1, teamId2, java.time.LocalDate.of(2024, 1, 1), 0, 0);
        MvcResult matchResult = mockMvc.perform(post("/api/matches")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(createDto))
                .cookie(new jakarta.servlet.http.Cookie("JWT_TOKEN", jwtToken)))
                .andExpect(status().isCreated())
                .andReturn();

        String matchContent = matchResult.getResponse().getContentAsString();
        com.example.courseworkLuchnetskyi.dto.response.MatchResponseDto createdMatch = objectMapper.readValue(matchContent, com.example.courseworkLuchnetskyi.dto.response.MatchResponseDto.class);
        Long matchId = createdMatch.id();

        // Update match
        var updateDto = new com.example.courseworkLuchnetskyi.dto.request.MatchRequestDto(tournamentId, teamId1, teamId2, java.time.LocalDate.of(2024, 1, 2), 0, 0);
        mockMvc.perform(put("/api/matches/" + matchId)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(updateDto))
                .cookie(new jakarta.servlet.http.Cookie("JWT_TOKEN", jwtToken)))
                .andExpect(status().isOk());
    }

    // Test 16: Delete match
    @Test
    public void testDeleteMatch_Unauthenticated_Fails() throws Exception {
        expectUnauthorized("/api/matches/1", "DELETE");
    }

    @Test
    public void testDeleteMatch_Authenticated_Succeeds() throws Exception {
        // Create tournament first
        TournamentRequestDto tournamentDto = new TournamentRequestDto("Tournament for Match", java.time.LocalDate.of(2024, 1, 1), java.time.LocalDate.of(2024, 1, 10), "Desc");
        MvcResult tournamentResult = mockMvc.perform(post("/api/tournaments")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(tournamentDto))
                .cookie(new jakarta.servlet.http.Cookie("JWT_TOKEN", jwtToken)))
                .andExpect(status().isCreated())
                .andReturn();

        String tournamentContent = tournamentResult.getResponse().getContentAsString();
        com.example.courseworkLuchnetskyi.dto.response.TournamentResponseDto createdTournament = objectMapper.readValue(tournamentContent, com.example.courseworkLuchnetskyi.dto.response.TournamentResponseDto.class);
        Long tournamentId = createdTournament.id();

        // Create teams
        var teamDto1 = new com.example.courseworkLuchnetskyi.dto.request.TeamRequestDto("Team 1", "Desc");
        MvcResult teamResult1 = mockMvc.perform(post("/api/teams")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(teamDto1))
                .cookie(new jakarta.servlet.http.Cookie("JWT_TOKEN", jwtToken)))
                .andExpect(status().isOk())
                .andReturn();
        String teamContent1 = teamResult1.getResponse().getContentAsString();
        com.example.courseworkLuchnetskyi.dto.response.TeamResponseDto createdTeam1 = objectMapper.readValue(teamContent1, com.example.courseworkLuchnetskyi.dto.response.TeamResponseDto.class);
        Long teamId1 = createdTeam1.id();

        var teamDto2 = new com.example.courseworkLuchnetskyi.dto.request.TeamRequestDto("Team 2", "Desc");
        MvcResult teamResult2 = mockMvc.perform(post("/api/teams")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(teamDto2))
                .cookie(new jakarta.servlet.http.Cookie("JWT_TOKEN", jwtToken)))
                .andExpect(status().isOk())
                .andReturn();
        String teamContent2 = teamResult2.getResponse().getContentAsString();
        com.example.courseworkLuchnetskyi.dto.response.TeamResponseDto createdTeam2 = objectMapper.readValue(teamContent2, com.example.courseworkLuchnetskyi.dto.response.TeamResponseDto.class);
        Long teamId2 = createdTeam2.id();

        // Create match
        var createDto = new com.example.courseworkLuchnetskyi.dto.request.MatchRequestDto(tournamentId, teamId1, teamId2, java.time.LocalDate.of(2024, 1, 1), 0, 0);
        MvcResult matchResult = mockMvc.perform(post("/api/matches")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(createDto))
                .cookie(new jakarta.servlet.http.Cookie("JWT_TOKEN", jwtToken)))
                .andExpect(status().isCreated())
                .andReturn();

        String matchContent = matchResult.getResponse().getContentAsString();
        com.example.courseworkLuchnetskyi.dto.response.MatchResponseDto createdMatch = objectMapper.readValue(matchContent, com.example.courseworkLuchnetskyi.dto.response.MatchResponseDto.class);
        Long matchId = createdMatch.id();

        // Delete match
        mockMvc.perform(delete("/api/matches/" + matchId)
                .cookie(new jakarta.servlet.http.Cookie("JWT_TOKEN", jwtToken)))
                .andExpect(status().isNoContent());
    }

    // Test 17: Add participation
    @Test
    public void testAddParticipation_Unauthenticated_Fails() throws Exception {
        expectUnauthorized("/api/participations", "POST");
    }

    @Test
    public void testAddParticipation_Authenticated_Succeeds() throws Exception {
        // Create tournament first
        TournamentRequestDto tournamentDto = new TournamentRequestDto("Tournament for Participation", java.time.LocalDate.of(2024, 1, 1), java.time.LocalDate.of(2024, 1, 10), "Desc");
        MvcResult tournamentResult = mockMvc.perform(post("/api/tournaments")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(tournamentDto))
                .cookie(new jakarta.servlet.http.Cookie("JWT_TOKEN", jwtToken)))
                .andExpect(status().isCreated())
                .andReturn();

        String tournamentContent = tournamentResult.getResponse().getContentAsString();
        com.example.courseworkLuchnetskyi.dto.response.TournamentResponseDto createdTournament = objectMapper.readValue(tournamentContent, com.example.courseworkLuchnetskyi.dto.response.TournamentResponseDto.class);
        Long tournamentId = createdTournament.id();

        // Create team with city field (fix for Team not found)
        var teamDto = new com.example.courseworkLuchnetskyi.dto.request.TeamRequestDto("Team for Participation", "City");
        MvcResult teamResult = mockMvc.perform(post("/api/teams")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(teamDto))
                .cookie(new jakarta.servlet.http.Cookie("JWT_TOKEN", jwtToken)))
                .andExpect(status().isOk())
                .andReturn();

        String teamContent = teamResult.getResponse().getContentAsString();
        com.example.courseworkLuchnetskyi.dto.response.TeamResponseDto createdTeam = objectMapper.readValue(teamContent, com.example.courseworkLuchnetskyi.dto.response.TeamResponseDto.class);
        Long teamId = createdTeam.id();

        // Create participation
        var dto = new com.example.courseworkLuchnetskyi.dto.request.ParticipationRequestDto(teamId, tournamentId);
        mockMvc.perform(post("/api/participations")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(dto))
                .cookie(new jakarta.servlet.http.Cookie("JWT_TOKEN", jwtToken)))
                .andExpect(status().isCreated());
    }

    // Test 18: Get teams by tournament
    @Test
    public void testGetTeamsByTournament_Unauthenticated_Fails() throws Exception {
        expectUnauthorized("/api/participations/tournament/1", "GET");
    }

    @Test
    public void testGetTeamsByTournament_Authenticated_Succeeds() throws Exception {
        // Create tournament first
        TournamentRequestDto tournamentDto = new TournamentRequestDto("Tournament for Participation", java.time.LocalDate.of(2024, 1, 1), java.time.LocalDate.of(2024, 1, 10), "Desc");
        MvcResult tournamentResult = mockMvc.perform(post("/api/tournaments")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(tournamentDto))
                .cookie(new jakarta.servlet.http.Cookie("JWT_TOKEN", jwtToken)))
                .andExpect(status().isCreated())
                .andReturn();

        String tournamentContent = tournamentResult.getResponse().getContentAsString();
        com.example.courseworkLuchnetskyi.dto.response.TournamentResponseDto createdTournament = objectMapper.readValue(tournamentContent, com.example.courseworkLuchnetskyi.dto.response.TournamentResponseDto.class);
        Long tournamentId = createdTournament.id();

        mockMvc.perform(get("/api/participations/tournament/" + tournamentId)
                .cookie(new jakarta.servlet.http.Cookie("JWT_TOKEN", jwtToken)))
                .andExpect(status().isOk());
    }

    // Test 19: Get tournaments by team
    @Test
    public void testGetTournamentsByTeam_Unauthenticated_Fails() throws Exception {
        expectUnauthorized("/api/participations/team/1", "GET");
    }

    @Test
    public void testGetTournamentsByTeam_Authenticated_Succeeds() throws Exception {
        // Create tournament first
        TournamentRequestDto tournamentDto = new TournamentRequestDto("Tournament for Participation", java.time.LocalDate.of(2024, 1, 1), java.time.LocalDate.of(2024, 1, 10), "Desc");
        MvcResult tournamentResult = mockMvc.perform(post("/api/tournaments")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(tournamentDto))
                .cookie(new jakarta.servlet.http.Cookie("JWT_TOKEN", jwtToken)))
                .andExpect(status().isCreated())
                .andReturn();

        String tournamentContent = tournamentResult.getResponse().getContentAsString();
        com.example.courseworkLuchnetskyi.dto.response.TournamentResponseDto createdTournament = objectMapper.readValue(tournamentContent, com.example.courseworkLuchnetskyi.dto.response.TournamentResponseDto.class);
        Long tournamentId = createdTournament.id();

        // Create team
        var teamDto = new com.example.courseworkLuchnetskyi.dto.request.TeamRequestDto("Team for Participation", "Desc");
        MvcResult teamResult = mockMvc.perform(post("/api/teams")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(teamDto))
                .cookie(new jakarta.servlet.http.Cookie("JWT_TOKEN", jwtToken)))
                .andExpect(status().isOk())
                .andReturn();

        String teamContent = teamResult.getResponse().getContentAsString();
        com.example.courseworkLuchnetskyi.dto.response.TeamResponseDto createdTeam = objectMapper.readValue(teamContent, com.example.courseworkLuchnetskyi.dto.response.TeamResponseDto.class);
        Long teamId = createdTeam.id();

        mockMvc.perform(get("/api/participations/team/" + teamId)
                .cookie(new jakarta.servlet.http.Cookie("JWT_TOKEN", jwtToken)))
                .andExpect(status().isOk());
    }

    // Test 20: Get tournament standings
    @Test
    public void testGetTournamentStandings_Unauthenticated_Fails() throws Exception {
        expectUnauthorized("/api/tournaments/1/standings", "GET");
    }

    @Test
    public void testGetTournamentStandings_Authenticated_Succeeds() throws Exception {
        // Create tournament first
        TournamentRequestDto tournamentDto = new TournamentRequestDto("Tournament for Standings", java.time.LocalDate.of(2024, 1, 1), java.time.LocalDate.of(2024, 1, 10), "Desc");
        MvcResult tournamentResult = mockMvc.perform(post("/api/tournaments")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(tournamentDto))
                .cookie(new jakarta.servlet.http.Cookie("JWT_TOKEN", jwtToken)))
                .andExpect(status().isCreated())
                .andReturn();

        String tournamentContent = tournamentResult.getResponse().getContentAsString();
        com.example.courseworkLuchnetskyi.dto.response.TournamentResponseDto createdTournament = objectMapper.readValue(tournamentContent, com.example.courseworkLuchnetskyi.dto.response.TournamentResponseDto.class);
        Long tournamentId = createdTournament.id();

        mockMvc.perform(get("/api/tournaments/" + tournamentId + "/standings")
                .cookie(new jakarta.servlet.http.Cookie("JWT_TOKEN", jwtToken)))
                .andExpect(status().isOk());
    }

    // Test 21: Get player statistics - assuming endpoint /api/players/statistics/{teamId}
    @Test
    public void testGetPlayerStatistics_Unauthenticated_Fails() throws Exception {
        expectUnauthorized("/api/players/statistics/1", "GET");
    }

    @Test
    public void testGetPlayerStatistics_Authenticated_Succeeds() throws Exception {
        // Create team first
        var teamDto = new com.example.courseworkLuchnetskyi.dto.request.TeamRequestDto("Team for Stats", "Desc");
        MvcResult teamResult = mockMvc.perform(post("/api/teams")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(teamDto))
                .cookie(new jakarta.servlet.http.Cookie("JWT_TOKEN", jwtToken)))
                .andExpect(status().isOk())
                .andReturn();

        String teamContent = teamResult.getResponse().getContentAsString();
        com.example.courseworkLuchnetskyi.dto.response.TeamResponseDto createdTeam = objectMapper.readValue(teamContent, com.example.courseworkLuchnetskyi.dto.response.TeamResponseDto.class);
        Long teamId = createdTeam.id();

        mockMvc.perform(get("/api/players/statistics/" + teamId)
                .cookie(new jakarta.servlet.http.Cookie("JWT_TOKEN", jwtToken)))
                .andExpect(status().isOk());
    }

    // Test 22: Get list of team matches - already tested in TeamController getMatchesForTeam
    // Test 23: Get match schedule of a tournament - already tested in MatchController getTournamentSchedule

    // Test 24: Get list of winners - assuming endpoint /api/tournaments/winners
    @Test
    public void testGetTournamentWinners_Unauthenticated_Fails() throws Exception {
        expectUnauthorized("/api/tournaments/winners", "GET");
    }

    @Test
    public void testGetTournamentWinners_Authenticated_Succeeds() throws Exception {
        mockMvc.perform(get("/api/tournaments/winners")
                .cookie(new jakarta.servlet.http.Cookie("JWT_TOKEN", jwtToken)))
                .andExpect(status().isOk());
    }

    // Test 25: Get average age of team players - assuming endpoint /api/players/average-age/{teamId}
    @Test
    public void testGetAverageAge_Unauthenticated_Fails() throws Exception {
        expectUnauthorized("/api/players/average-age/1", "GET");
    }

    @Test
    public void testGetAverageAge_Authenticated_Succeeds() throws Exception {
        // Create team first
        var teamDto = new com.example.courseworkLuchnetskyi.dto.request.TeamRequestDto("Team for Avg Age", "Desc");
        MvcResult teamResult = mockMvc.perform(post("/api/teams")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(teamDto))
                .cookie(new jakarta.servlet.http.Cookie("JWT_TOKEN", jwtToken)))
                .andExpect(status().isOk())
                .andReturn();

        String teamContent = teamResult.getResponse().getContentAsString();
        com.example.courseworkLuchnetskyi.dto.response.TeamResponseDto createdTeam = objectMapper.readValue(teamContent, com.example.courseworkLuchnetskyi.dto.response.TeamResponseDto.class);
        Long teamId = createdTeam.id();

        // Create player for the team
        var playerDto = new com.example.courseworkLuchnetskyi.dto.request.PlayerRequestDto("Player1", java.time.LocalDate.of(2000, 1, 1), "Position", teamId);
        mockMvc.perform(post("/api/players")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(playerDto))
                .cookie(new jakarta.servlet.http.Cookie("JWT_TOKEN", jwtToken)))
                .andExpect(status().isCreated());

        mockMvc.perform(get("/api/players/average-age/" + teamId)
                .cookie(new jakarta.servlet.http.Cookie("JWT_TOKEN", jwtToken)))
                .andExpect(status().isOk());
    }
}